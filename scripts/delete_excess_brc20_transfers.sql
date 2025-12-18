-- Delete Excess BRC-20 Transfers
--
-- This script removes all but the first 2 transfers for BRC-20 inscriptions
-- to reduce database storage. It processes one inscription at a time to avoid
-- temporary file size limits and memory issues.
--
-- Usage:
--   psql -U postgres -d vermilion -f delete_excess_brc20_transfers.sql
--
-- Or run directly in psql:
--   \i scripts/delete_excess_brc20_transfers.sql
--
-- Progress is logged every 100 inscriptions processed.
-- Safe to interrupt (Ctrl+C) and restart - it will process remaining inscriptions.

CREATE OR REPLACE PROCEDURE delete_excess_brc20_transfers_proc()
LANGUAGE plpgsql
AS $$
DECLARE
  inscription_rec RECORD;
  counter int := 0;
  total_deleted bigint := 0;
  rows_deleted bigint;
  start_seq_num int := 0;  -- Start from this sequence number
BEGIN
  RAISE NOTICE 'Starting BRC-20 transfer cleanup from sequence_number %...', start_seq_num;

  FOR inscription_rec IN
    SELECT id, sequence_number FROM ordinals
    WHERE text ILIKE '%brc-20%'
    AND sequence_number >= start_seq_num
    ORDER BY sequence_number
  LOOP
    -- Delete excess transfers for this one inscription
    -- Keeps only the first 2 transfers (genesis + first transfer)
    -- Uses OFFSET for faster performance
    DELETE FROM transfers
    WHERE ctid IN (
      SELECT ctid FROM transfers
      WHERE id = inscription_rec.id
      ORDER BY block_number ASC, tx_offset ASC
      OFFSET 2  -- Skip first 2, delete the rest
    );

    GET DIAGNOSTICS rows_deleted = ROW_COUNT;
    total_deleted := total_deleted + rows_deleted;
    counter := counter + 1;

    -- Commit after each iteration
    COMMIT;

    -- Progress update every 100 inscriptions
    IF counter % 100 = 0 THEN
      RAISE NOTICE 'Processed % inscriptions (seq_num: %), deleted % total transfers',
        counter, inscription_rec.sequence_number, total_deleted;
    END IF;
  END LOOP;

  RAISE NOTICE 'DONE! Processed % inscriptions, deleted % total transfers', counter, total_deleted;
  RAISE NOTICE 'Run "VACUUM FULL transfers;" to reclaim disk space';
END $$;
