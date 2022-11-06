package com.example.reddit.repository;

import com.example.reddit.model.Post;
import com.example.reddit.model.RedditUser;
import com.example.reddit.model.Subreddit;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface PostRepository extends JpaRepository<Post, Long> {
    List<Post> findAllBySubreddit(Subreddit subreddit);

    List<Post> findByUser(RedditUser user);
}
