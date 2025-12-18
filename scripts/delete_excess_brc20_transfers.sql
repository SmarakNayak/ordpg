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

DO $$
DECLARE
  inscription_rec RECORD;
  counter int := 0;
  total_deleted bigint := 0;
  rows_deleted bigint;
BEGIN
  RAISE NOTICE 'Starting BRC-20 transfer cleanup...';

  FOR inscription_rec IN
    SELECT id, sequence_number FROM ordinals
    WHERE text ILIKE '%brc-20%'
    ORDER BY sequence_number
  LOOP
    -- Delete excess transfers for this one inscription
    -- Keeps only the first 2 transfers (genesis + first transfer)
    DELETE FROM transfers
    WHERE id = inscription_rec.id
    AND (block_number, tx_offset) NOT IN (
      SELECT block_number, tx_offset
      FROM (
        SELECT block_number, tx_offset,
               ROW_NUMBER() OVER (ORDER BY block_number ASC, tx_offset ASC) as rn
        FROM transfers
        WHERE id = inscription_rec.id
      ) ranked
      WHERE rn <= 2
    );

    GET DIAGNOSTICS rows_deleted = ROW_COUNT;
    total_deleted := total_deleted + rows_deleted;
    counter := counter + 1;

    -- Progress update every 100 inscriptions
    IF counter % 100 = 0 THEN
      RAISE NOTICE 'Processed % inscriptions (seq_num: %), deleted % total transfers',
        counter, inscription_rec.sequence_number, total_deleted;
    END IF;
  END LOOP;

  RAISE NOTICE 'DONE! Processed % inscriptions, deleted % total transfers', counter, total_deleted;
  RAISE NOTICE 'Run "VACUUM FULL transfers;" to reclaim disk space';
END $$;
