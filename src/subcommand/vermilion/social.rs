struct user {
  user_id: u64,
  user_name: String,
  user_addresses: Vec<String>,
  user_picture: Option<String>,
  user_bio: Option<String>,
  user_twitter: Option<String>,
  user_discord: Option<String>,
  user_website: Option<String>,
  created_at: u64,
}

struct follow {
  follower_id: u64,
  following_id: u64,
  created_at: u64,
}

struct like {  
  inscription_id: u64,
  user_id: u64,
  created_at: u64,
}

struct comment {
  comment_id: u64,
  inscription_id: u64,
  user_id: u64,
  comment: String,
  parent_comment_id: Option<u64>,
  created_at: u64,
}

struct playlist_info {
  playlist_id: u64,
  user_id: u64,
  playlist_name: String,
  playlist_picture: Option<String>,
  playlist_description: Option<String>,
  playlist_twitter: Option<String>,
  playlist_discord: Option<String>,
  playlist_website: Option<String>,
  created_at: u64,
}

struct playlist_inscriptions {
  playlist_id: u64,
  inscription_id: u64
}