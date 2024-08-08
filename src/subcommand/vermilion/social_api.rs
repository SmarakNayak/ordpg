use super::*;
use self::social::*;
use axum::{
  routing::get,
  routing::post,
  routing::put,
  routing::delete,
};

//API
pub fn social_router() -> Router<ApiServerConfig> {
  let app = Router::new()
    .route("/social/user", post(create_user_handler))    
    .route("/social/user/:user_id", get(get_user_handler))
    .route("/social/user/:user_id", put(update_user_handler))
    .route("/social/user/:user_id", delete(delete_user_handler))
    .route("/social/follow", post(create_follow_handler))
    .route("/social/follow/:user_id", get(get_follows_handler))
    .route("/social/follow/:follower_id/:following_id", delete(delete_follow_handler))
    .route("/social/followers/:user_id", get(get_followers_handler))
    .route("/social/like", post(create_like_handler))
    .route("/social/like/:inscription_id", get(get_likes_handler))
    .route("/social/like/:inscription_id/:user_id", delete(delete_like_handler))
    .route("/social/comment", post(create_comment_handler))
    .route("/social/comment/:inscription_id", get(get_comments_handler))
    .route("/social/comment/:comment_id", put(update_comment_handler))
    .route("/social/comment/:comment_id", delete(delete_comment_handler))
    .route("/social/playlist_info", post(create_playlist_info_handler))
    .route("/social/playlist_info/:playlist_id", put(update_playlist_info_handler))
    .route("/social/playlist_info/:playlist_id", delete(delete_playlist_info_handler))
    .route("/social/playlist_inscription", post(create_playlist_inscription_handler))
    .route("/social/playlist_inscription/:playlist_id", get(get_playlist_inscriptions_handler))
    .route("/social/playlist_inscription/:playlist_id/:inscription_id", delete(delete_playlist_inscription_handler))
    .route("/social/playlists/:user_id", get(get_playlists_handler));
  app
}

async fn create_user_handler(State(server_config): State<ApiServerConfig>, Json(user): Json<User>) -> impl axum::response::IntoResponse {
  match insert_user(&server_config.deadpool, &user).await {
    Ok(_) => StatusCode::CREATED,
    Err(error) => {
      log::warn!("Error creating /user: {}", error);
      return (
        StatusCode::INTERNAL_SERVER_ERROR,
        "Error creating user",
      ).into_response();
    }
  }.into_response()
}

async fn create_follow_handler(State(server_config): State<ApiServerConfig>, Json(follow): Json<Follow>) -> impl axum::response::IntoResponse {
  match insert_follow(&server_config.deadpool, &follow).await {
    Ok(_) => StatusCode::CREATED,
    Err(error) => {
      log::warn!("Error creating /follow: {}", error);
      return (
        StatusCode::INTERNAL_SERVER_ERROR,
        "Error creating follow",
      ).into_response();
    }
  }.into_response()
}

async fn create_like_handler(State(server_config): State<ApiServerConfig>, Json(like): Json<Like>) -> impl axum::response::IntoResponse {
  match insert_like(&server_config.deadpool, &like).await {
    Ok(_) => StatusCode::CREATED,
    Err(error) => {
      log::warn!("Error creating /like: {}", error);
      return (
        StatusCode::INTERNAL_SERVER_ERROR,
        "Error creating like",
      ).into_response();
    }
  }.into_response()
}

async fn create_comment_handler(State(server_config): State<ApiServerConfig>, Json(comment): Json<Comment>) -> impl axum::response::IntoResponse {
  match insert_comment(&server_config.deadpool, &comment).await {
    Ok(_) => StatusCode::CREATED,
    Err(error) => {
      log::warn!("Error creating /comment: {}", error);
      return (
        StatusCode::INTERNAL_SERVER_ERROR,
        "Error creating comment",
      ).into_response();
    }
  }.into_response()
}

async fn create_playlist_info_handler(State(server_config): State<ApiServerConfig>, Json(playlist_info): Json<PlaylistInfo>) -> impl axum::response::IntoResponse {
  match insert_playlist_info(&server_config.deadpool, &playlist_info).await {
    Ok(_) => StatusCode::CREATED,
    Err(error) => {
      log::warn!("Error creating /playlist_info: {}", error);
      return (
        StatusCode::INTERNAL_SERVER_ERROR,
        "Error creating playlist",
      ).into_response();
    }
  }.into_response()
}

async fn create_playlist_inscription_handler(State(server_config): State<ApiServerConfig>, Json(playlist_inscription): Json<PlaylistInscription>) -> impl axum::response::IntoResponse {
  match insert_playlist_inscription(&server_config.deadpool, &playlist_inscription).await {
    Ok(_) => StatusCode::CREATED,
    Err(error) => {
      log::warn!("Error creating /playlist_inscription: {}", error);
      return (
        StatusCode::INTERNAL_SERVER_ERROR,
        "Error creating inscription",
      ).into_response();
    }
  }.into_response()
}

async fn get_user_handler(Path(user_id): Path<i64>, State(server_config): State<ApiServerConfig>) -> impl axum::response::IntoResponse {
  let user = match get_user(&server_config.deadpool, user_id).await {
    Ok(user) => user,
    Err(error) => {
      log::warn!("Error getting /user: {}", error);
      return (
        StatusCode::INTERNAL_SERVER_ERROR,
        format!("Error retrieving user for {}", user_id),
      ).into_response();
    }
  };
  Json(user).into_response()
}

async fn get_follows_handler(Path(user_id): Path<i64>, State(server_config): State<ApiServerConfig>) -> impl axum::response::IntoResponse {
  let follows = match get_follows(&server_config.deadpool, user_id).await {
    Ok(follows) => follows,
    Err(error) => {
      log::warn!("Error getting /follows: {}", error);
      return (
        StatusCode::INTERNAL_SERVER_ERROR,
        format!("Error retrieving follows for {}", user_id),
      ).into_response();
    }
  };
  Json(follows).into_response()
}

async fn get_followers_handler(Path(user_id): Path<i64>, State(server_config): State<ApiServerConfig>) -> impl axum::response::IntoResponse {
  let followers = match get_followers(&server_config.deadpool, user_id).await {
    Ok(followers) => followers,
    Err(error) => {
      log::warn!("Error getting /followers: {}", error);
      return (
        StatusCode::INTERNAL_SERVER_ERROR,
        format!("Error retrieving followers for {}", user_id),
      ).into_response();
    }
  };
  Json(followers).into_response()
}

async fn get_likes_handler(Path(inscription_id): Path<String>, State(server_config): State<ApiServerConfig>) -> impl axum::response::IntoResponse {
  let likes = match get_likes(&server_config.deadpool, &inscription_id).await {
    Ok(likes) => likes,
    Err(error) => {
      log::warn!("Error getting /likes: {}", error);
      return (
        StatusCode::INTERNAL_SERVER_ERROR,
        format!("Error retrieving likes for {}", inscription_id),
      ).into_response();
    }
  };
  Json(likes).into_response()
}

async fn get_comments_handler(Path(inscription_id): Path<String>, State(server_config): State<ApiServerConfig>) -> impl axum::response::IntoResponse {
  let comments = match get_comments(&server_config.deadpool, &inscription_id).await {
    Ok(comments) => comments,
    Err(error) => {
      log::warn!("Error getting /comments: {}", error);
      return (
        StatusCode::INTERNAL_SERVER_ERROR,
        format!("Error retrieving comments for {}", inscription_id),
      ).into_response();
    }
  };
  Json(comments).into_response()
}

async fn get_playlists_handler(Path(user_id): Path<i64>, State(server_config): State<ApiServerConfig>) -> impl axum::response::IntoResponse {
  let playlists = match get_playlists(&server_config.deadpool, user_id).await {
    Ok(playlists) => playlists,
    Err(error) => {
      log::warn!("Error getting /playlists: {}", error);
      return (
        StatusCode::INTERNAL_SERVER_ERROR,
        format!("Error retrieving playlists for {}", user_id),
      ).into_response();
    }
  };
  Json(playlists).into_response()
}

async fn get_playlist_inscriptions_handler(Path(playlist_id): Path<i64>, State(server_config): State<ApiServerConfig>) -> impl axum::response::IntoResponse {
  let inscriptions = match get_playlist_inscriptions(&server_config.deadpool, playlist_id).await {
    Ok(inscriptions) => inscriptions,
    Err(error) => {
      log::warn!("Error getting /playlist_inscriptions: {}", error);
      return (
        StatusCode::INTERNAL_SERVER_ERROR,
        format!("Error retrieving inscriptions for playlist {}", playlist_id),
      ).into_response();
    }
  };
  Json(inscriptions).into_response()
}

async fn delete_user_handler(Path(user_id): Path<i64>, State(server_config): State<ApiServerConfig>) -> impl axum::response::IntoResponse {
  match delete_user(&server_config.deadpool, user_id).await {
    Ok(_) => (),
    Err(error) => {
      log::warn!("Error deleting /user: {}", error);
      return (
        StatusCode::INTERNAL_SERVER_ERROR,
        format!("Error deleting user {}", user_id),
      ).into_response();
    }
  };
  StatusCode::NO_CONTENT.into_response()
}

async fn delete_follow_handler(Path(follower_id): Path<i64>, Path(following_id): Path<i64>, State(server_config): State<ApiServerConfig>) -> impl axum::response::IntoResponse {
  match delete_follow(&server_config.deadpool, follower_id, following_id).await {
    Ok(_) => (),
    Err(error) => {
      log::warn!("Error deleting /follow: {}", error);
      return (
        StatusCode::INTERNAL_SERVER_ERROR,
        format!("Error deleting follow from {} to {}", follower_id, following_id),
      ).into_response();
    }
  };
  StatusCode::NO_CONTENT.into_response()
}

async fn delete_like_handler(Path(inscription_id): Path<String>, Path(user_id): Path<i64>, State(server_config): State<ApiServerConfig>) -> impl axum::response::IntoResponse {
  match delete_like(&server_config.deadpool, inscription_id.clone(), user_id).await {
    Ok(_) => (),
    Err(error) => {
      log::warn!("Error deleting /like: {}", error);
      return (
        StatusCode::INTERNAL_SERVER_ERROR,
        format!("Error deleting like for {} by {}", inscription_id, user_id),
      ).into_response();
    }
  };
  StatusCode::NO_CONTENT.into_response()
}

async fn delete_comment_handler(Path(comment_id): Path<i64>, State(server_config): State<ApiServerConfig>) -> impl axum::response::IntoResponse {
  match delete_comment(&server_config.deadpool, comment_id).await {
    Ok(_) => (),
    Err(error) => {
      log::warn!("Error deleting /comment: {}", error);
      return (
        StatusCode::INTERNAL_SERVER_ERROR,
        format!("Error deleting comment {}", comment_id),
      ).into_response();
    }
  };
  StatusCode::NO_CONTENT.into_response()
}

async fn delete_playlist_info_handler(Path(playlist_id): Path<i64>, State(server_config): State<ApiServerConfig>) -> impl axum::response::IntoResponse {
  match delete_playlist_info(&server_config.deadpool, playlist_id).await {
    Ok(_) => (),
    Err(error) => {
      log::warn!("Error deleting /playlist_info: {}", error);
      return (
        StatusCode::INTERNAL_SERVER_ERROR,
        format!("Error deleting playlist {}", playlist_id),
      ).into_response();
    }
  };
  StatusCode::NO_CONTENT.into_response()
}

async fn delete_playlist_inscription_handler(Path(playlist_id): Path<i64>, Path(inscription_id): Path<String>, State(server_config): State<ApiServerConfig>) -> impl axum::response::IntoResponse {
  match delete_playlist_inscription(&server_config.deadpool, playlist_id, &inscription_id).await {
    Ok(_) => (),
    Err(error) => {
      log::warn!("Error deleting /playlist_inscription: {}", error);
      return (
        StatusCode::INTERNAL_SERVER_ERROR,
        format!("Error deleting inscription {} from playlist {}", inscription_id, playlist_id),
      ).into_response();
    }
  };
  StatusCode::NO_CONTENT.into_response()
}

async fn update_user_handler(Path(user_id): Path<i64>, State(server_config): State<ApiServerConfig>, Json(user): Json<User>) -> impl axum::response::IntoResponse {
  match update_user(&server_config.deadpool, &user).await {
    Ok(_) => (),
    Err(error) => {
      log::warn!("Error updating /user: {}", error);
      return (
        StatusCode::INTERNAL_SERVER_ERROR,
        format!("Error updating user {}", user_id),
      ).into_response();
    }
  };
  StatusCode::NO_CONTENT.into_response()
}

async fn update_comment_handler(Path(comment_id): Path<i64>, State(server_config): State<ApiServerConfig>, Json(comment): Json<Comment>) -> impl axum::response::IntoResponse {
  match update_comment(&server_config.deadpool, &comment).await {
    Ok(_) => (),
    Err(error) => {
      log::warn!("Error updating /comment: {}", error);
      return (
        StatusCode::INTERNAL_SERVER_ERROR,
        format!("Error updating comment {}", comment_id),
      ).into_response();
    }
  };
  StatusCode::NO_CONTENT.into_response()
}

async fn update_playlist_info_handler(Path(playlist_id): Path<i64>, State(server_config): State<ApiServerConfig>, Json(playlist_info): Json<PlaylistInfo>) -> impl axum::response::IntoResponse {
  match update_playlist_info(&server_config.deadpool, &playlist_info).await {
    Ok(_) => (),
    Err(error) => {
      log::warn!("Error updating /playlist_info: {}", error);
      return (
        StatusCode::INTERNAL_SERVER_ERROR,
        format!("Error updating playlist {}", playlist_id),
      ).into_response();
    }
  };
  StatusCode::NO_CONTENT.into_response()
}


