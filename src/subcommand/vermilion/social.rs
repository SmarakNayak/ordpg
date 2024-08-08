use super::*;

#[derive(Debug, Serialize, Deserialize)]
pub struct User {
  user_id: Option<i64>,
  user_name: String,
  user_addresses: Vec<String>,
  user_picture: Option<String>,
  user_bio: Option<String>,
  user_twitter: Option<String>,
  user_discord: Option<String>,
  user_website: Option<String>,
  created_at: Option<i64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Follow {
  follower_id: i64,
  following_id: i64,
  created_at: Option<i64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Like {  
  inscription_id: String,
  user_id: i64,
  created_at: Option<i64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Comment {
  comment_id: i64,
  inscription_id: String,
  user_id: i64,
  comment: String,
  parent_comment_id: Option<i64>,
  created_at: Option<i64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PlaylistInfo {
  playlist_id: Option<i64>,
  user_id: i64,
  playlist_name: String,
  playlist_picture: Option<String>,
  playlist_description: Option<String>,
  playlist_twitter: Option<String>,
  playlist_discord: Option<String>,
  playlist_website: Option<String>,
  created_at: Option<i64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PlaylistInscription {
  playlist_id: i64,
  inscription_id: String,
  added_at: Option<i64>,
}

pub async fn initialize_social_tables(pool: deadpool) -> anyhow::Result<()> {
  create_users_table(pool.clone()).await.context("Failed to create users table")?;
  create_follows_table(pool.clone()).await.context("Failed to create follows table")?;
  create_likes_table(pool.clone()).await.context("Failed to create likes table")?;
  create_comments_table(pool.clone()).await.context("Failed to create comments table")?;
  create_playlist_info_table(pool.clone()).await.context("Failed to create playlist info table")?;
  create_playlist_inscriptions_table(pool.clone()).await.context("Failed to create playlist inscriptions table")?;
  Ok(())
}

async fn create_users_table(pool: deadpool) -> anyhow::Result<()> {
  let conn = pool.get().await?;
  conn.simple_query(r"
    CREATE TABLE IF NOT EXISTS users (
      user_id bigserial PRIMARY KEY,
      user_name varchar(15) UNIQUE,
      user_addresses varchar(80)[],
      user_picture varchar(80),
      user_bio varchar(160),
      user_twitter varchar(20),
      user_discord varchar(20),
      user_website varchar(50),
      created_at bigint
    )").await?;
  Ok(())
}

async fn create_follows_table(pool: deadpool) -> anyhow::Result<()> {
  let conn = pool.get().await?;
  conn.simple_query(r"
    CREATE TABLE IF NOT EXISTS follows (
      follower_id bigint,
      following_id bigint,
      created_at bigint,
      PRIMARY KEY (follower_id, following_id)
    )").await?;
  Ok(())
}

async fn create_likes_table(pool: deadpool) -> anyhow::Result<()> {
  let conn = pool.get().await?;
  conn.simple_query(r"
    CREATE TABLE IF NOT EXISTS likes (
      inscription_id varchar(80),
      user_id bigint,
      created_at bigint,
      PRIMARY KEY (inscription_id, user_id)
    )").await?;
  Ok(())
}

async fn create_comments_table(pool: deadpool) -> anyhow::Result<()> {
  let conn = pool.get().await?;
  conn.simple_query(r"
    CREATE TABLE IF NOT EXISTS comments (
      comment_id bigserial PRIMARY KEY,
      inscription_id varchar(80),
      user_id bigint,
      comment varchar(280),
      parent_comment_id bigint,
      created_at bigint
    )").await?;
  Ok(())
}

async fn create_playlist_info_table(pool: deadpool) -> anyhow::Result<()> {
  let conn = pool.get().await?;
  conn.simple_query(r"
    CREATE TABLE IF NOT EXISTS playlist_info (
      playlist_id bigserial PRIMARY KEY,
      user_id bigint,
      playlist_name varchar(15),
      playlist_picture varchar(80),
      playlist_description varchar(160),
      playlist_twitter varchar(20),
      playlist_discord varchar(20),
      playlist_website varchar(50),
      created_at bigint
    )").await?;
  Ok(())
}

async fn create_playlist_inscriptions_table(pool: deadpool) -> anyhow::Result<()> {
  let conn = pool.get().await?;
  conn.simple_query(r"
    CREATE TABLE IF NOT EXISTS playlist_inscriptions (
      playlist_id bigint,
      inscription_id varchar(80),
      added_at bigint,
      PRIMARY KEY (playlist_id, inscription_id)
    )").await?;
  Ok(())
}

pub async fn insert_user(pool: &deadpool, user: &User) -> anyhow::Result<i64> {
  let conn = pool.get().await?;
  let row = conn.query_one(r"
      INSERT INTO users (user_name, user_addresses, user_picture, user_bio, user_twitter, user_discord, user_website, created_at)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
      RETURNING user_id
  ", &[&user.user_name, &user.user_addresses, &user.user_picture, &user.user_bio, &user.user_twitter, &user.user_discord, &user.user_website, &user.created_at]).await?;
  Ok(row.get(0))
}

pub async fn insert_follow(pool: &deadpool, follow: &Follow) -> anyhow::Result<()> {
  let conn = pool.get().await?;
  conn.execute(r"
      INSERT INTO follows (follower_id, following_id, created_at)
      VALUES ($1, $2, $3)
  ", &[&follow.follower_id, &follow.following_id, &follow.created_at]).await?;
  Ok(())
}

pub async fn insert_like(pool: &deadpool, like: &Like) -> anyhow::Result<()> {
  let conn = pool.get().await?;
  conn.execute(r"
      INSERT INTO likes (inscription_id, user_id, created_at)
      VALUES ($1, $2, $3)
  ", &[&like.inscription_id, &like.user_id, &like.created_at]).await?;
  Ok(())
}

pub async fn insert_comment(pool: &deadpool, comment: &Comment) -> anyhow::Result<i64> {
  let conn = pool.get().await?;
  let row = conn.query_one(r"
      INSERT INTO comments (inscription_id, user_id, comment, parent_comment_id, created_at)
      VALUES ($1, $2, $3, $4, $5)
      RETURNING comment_id
  ", &[&comment.inscription_id, &comment.user_id, &comment.comment, &comment.parent_comment_id, &comment.created_at]).await?;
  Ok(row.get(0))
}

pub async fn insert_playlist_info(pool: &deadpool, playlist_info: &PlaylistInfo) -> anyhow::Result<i64> {
  let conn = pool.get().await?;
  let row = conn.query_one(r"
      INSERT INTO playlist_info (user_id, playlist_name, playlist_picture, playlist_description, playlist_twitter, playlist_discord, playlist_website, created_at)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
      RETURNING playlist_id
  ", &[&playlist_info.user_id, &playlist_info.playlist_name, &playlist_info.playlist_picture, &playlist_info.playlist_description, &playlist_info.playlist_twitter, &playlist_info.playlist_discord, &playlist_info.playlist_website, &playlist_info.created_at]).await?;
  Ok(row.get(0))
}

pub async fn insert_playlist_inscription(pool: &deadpool, playlist_inscription: &PlaylistInscription) -> anyhow::Result<()> {
  let conn = pool.get().await?;
  conn.execute(r"
      INSERT INTO playlist_inscriptions (playlist_id, inscription_id, added_at)
      VALUES ($1, $2, $3)
  ", &[&playlist_inscription.playlist_id, &playlist_inscription.inscription_id, &playlist_inscription.added_at]).await?;
  Ok(())
}

// User updates and deletes
pub async fn update_user(pool: &deadpool, user: &User) -> anyhow::Result<()> {
  let conn = pool.get().await?;
  conn.execute(r"
      UPDATE users SET 
      user_name = $2, user_addresses = $3, user_picture = $4, user_bio = $5, 
      user_twitter = $6, user_discord = $7, user_website = $8
      WHERE user_id = $1
  ", &[&user.user_id, &user.user_name, &user.user_addresses, &user.user_picture, 
      &user.user_bio, &user.user_twitter, &user.user_discord, &user.user_website]).await?;
  Ok(())
}

pub async fn delete_user(pool: &deadpool, user_id: i64) -> anyhow::Result<()> {
  let conn = pool.get().await?;
  conn.execute("DELETE FROM users WHERE user_id = $1", &[&user_id]).await?;
  Ok(())
}

// Follow deletes (no update as it's a simple relationship)
pub async fn delete_follow(pool: &deadpool, follower_id: i64, following_id: i64) -> anyhow::Result<()> {
  let conn = pool.get().await?;
  conn.execute("DELETE FROM follows WHERE follower_id = $1 AND following_id = $2", 
               &[&follower_id, &following_id]).await?;
  Ok(())
}

// Like deletes (no update as it's a simple relationship)
pub async fn delete_like(pool: &deadpool, inscription_id: String, user_id: i64) -> anyhow::Result<()> {
  let conn = pool.get().await?;
  conn.execute("DELETE FROM likes WHERE inscription_id = $1 AND user_id = $2", 
               &[&inscription_id, &user_id]).await?;
  Ok(())
}

// Comment updates and deletes
pub async fn update_comment(pool: &deadpool, comment: &Comment) -> anyhow::Result<()> {
  let conn = pool.get().await?;
  conn.execute(r"
      UPDATE comments SET 
      inscription_id = $2, user_id = $3, comment = $4, parent_comment_id = $5
      WHERE comment_id = $1
  ", &[&comment.comment_id, &comment.inscription_id, &comment.user_id, 
      &comment.comment, &comment.parent_comment_id]).await?;
  Ok(())
}

pub async fn delete_comment(pool: &deadpool, comment_id: i64) -> anyhow::Result<()> {
  let conn = pool.get().await?;
  conn.execute("DELETE FROM comments WHERE comment_id = $1", &[&comment_id]).await?;
  Ok(())
}

// PlaylistInfo updates and deletes
pub async fn update_playlist_info(pool: &deadpool, playlist_info: &PlaylistInfo) -> anyhow::Result<()> {
  let conn = pool.get().await?;
  conn.execute(r"
      UPDATE playlist_info SET 
      user_id = $2, playlist_name = $3, playlist_picture = $4, playlist_description = $5,
      playlist_twitter = $6, playlist_discord = $7, playlist_website = $8
      WHERE playlist_id = $1
  ", &[&playlist_info.playlist_id, &playlist_info.user_id, &playlist_info.playlist_name, 
      &playlist_info.playlist_picture, &playlist_info.playlist_description, 
      &playlist_info.playlist_twitter, &playlist_info.playlist_discord, 
      &playlist_info.playlist_website]).await?;
  Ok(())
}

pub async fn delete_playlist_info(pool: &deadpool, playlist_id: i64) -> anyhow::Result<()> {
  let conn = pool.get().await?;
  conn.execute("DELETE FROM playlist_info WHERE playlist_id = $1", &[&playlist_id]).await?;
  Ok(())
}

// PlaylistInscriptions deletes (no update as it's a simple relationship)
pub async fn delete_playlist_inscription(pool: &deadpool, playlist_id: i64, inscription_id: &str) -> anyhow::Result<()> {
  let conn = pool.get().await?;
  conn.execute("DELETE FROM playlist_inscriptions WHERE playlist_id = $1 AND inscription_id = $2", 
               &[&playlist_id, &inscription_id]).await?;
  Ok(())
}

pub async fn get_user(pool: &deadpool, user_id: i64) -> anyhow::Result<User> {
  let conn = pool.get().await?;
  let row = conn.query_one("SELECT * FROM users WHERE user_id = $1", &[&user_id]).await?;
  Ok(User {
    user_id: Some(row.get("user_id")),
    user_name: row.get("user_name"),
    user_addresses: row.get("user_addresses"),
    user_picture: row.get("user_picture"),
    user_bio: row.get("user_bio"),
    user_twitter: row.get("user_twitter"),
    user_discord: row.get("user_discord"),
    user_website: row.get("user_website"),
    created_at: row.get("created_at"),
  })
}

pub async fn get_follows(pool: &deadpool, follower_id: i64) -> anyhow::Result<Vec<Follow>> {
  let conn = pool.get().await?;
  let rows = conn.query("SELECT * FROM follows WHERE follower_id = $1", &[&follower_id]).await?;
  let mut follows = Vec::new();
  for row in rows {
    follows.push(Follow {
      follower_id: row.get("follower_id"),
      following_id: row.get("following_id"),
      created_at: row.get("created_at"),
    });
  }
  Ok(follows)
}

pub async fn get_followers(pool: &deadpool, following_id: i64) -> anyhow::Result<Vec<Follow>> {
  let conn = pool.get().await?;
  let rows = conn.query("SELECT * FROM follows WHERE following_id = $1", &[&following_id]).await?;
  let mut follows = Vec::new();
  for row in rows {
    follows.push(Follow {
      follower_id: row.get("follower_id"),
      following_id: row.get("following_id"),
      created_at: row.get("created_at"),
    });
  }
  Ok(follows)
}

pub async fn get_likes(pool: &deadpool, inscription_id: &str) -> anyhow::Result<Vec<Like>> {
  let conn = pool.get().await?;
  let rows = conn.query("SELECT * FROM likes WHERE inscription_id = $1", &[&inscription_id]).await?;
  let mut likes = Vec::new();
  for row in rows {
    likes.push(Like {
      inscription_id: row.get("inscription_id"),
      user_id: row.get("user_id"),
      created_at: row.get("created_at"),
    });
  }
  Ok(likes)
}

pub async fn get_comments(pool: &deadpool, inscription_id: &str) -> anyhow::Result<Vec<Comment>> {
  let conn = pool.get().await?;
  let rows = conn.query("SELECT * FROM comments WHERE inscription_id = $1", &[&inscription_id]).await?;
  let mut comments = Vec::new();
  for row in rows {
    comments.push(Comment {
      comment_id: row.get("comment_id"),
      inscription_id: row.get("inscription_id"),
      user_id: row.get("user_id"),
      comment: row.get("comment"),
      parent_comment_id: row.get("parent_comment_id"),
      created_at: row.get("created_at"),
    });
  }
  Ok(comments)
}

pub async fn get_playlists(pool: &deadpool, user_id: i64) -> anyhow::Result<Vec<PlaylistInfo>> {
  let conn = pool.get().await?;
  let rows = conn.query("SELECT * FROM playlist_info WHERE user_id = $1", &[&user_id]).await?;
  let mut playlists = Vec::new();
  for row in rows {
    playlists.push(PlaylistInfo {
      playlist_id: Some(row.get("playlist_id")),
      user_id: row.get("user_id"),
      playlist_name: row.get("playlist_name"),
      playlist_picture: row.get("playlist_picture"),
      playlist_description: row.get("playlist_description"),
      playlist_twitter: row.get("playlist_twitter"),
      playlist_discord: row.get("playlist_discord"),
      playlist_website: row.get("playlist_website"),
      created_at: row.get("created_at"),
    });
  }
  Ok(playlists)
}

pub async fn get_playlist_inscriptions(pool: &deadpool, playlist_id: i64) -> anyhow::Result<Vec<PlaylistInscription>> {
  let conn = pool.get().await?;
  let rows = conn.query("SELECT * FROM playlist_inscriptions WHERE playlist_id = $1", 
                        &[&playlist_id]).await?;
  let mut inscriptions = Vec::new();
  for row in rows {
    inscriptions.push(PlaylistInscription {
      playlist_id: row.get("playlist_id"),
      inscription_id: row.get("inscription_id"),
      added_at: row.get("added_at"),
    });
  }
  Ok(inscriptions)
}
