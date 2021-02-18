---
layout: page
title: Blog
isroot: True
order: 2
permalink: /blog/
---

<h1 class="page-heading">Posts</h1>
<p class="rss-subscribe footer">subscribe <a href="{{ "/feed.xml" | prepend: site.baseurl }}">via RSS</a></p>
<ul class="post-list">
  {% for post in site.categories.blog %}
    <li>
      <span class="post-meta">{{ post.date | date: "%b %-d, %Y" }}</span>

      <h2>
        <a class="post-link" href="{{ post.url | prepend: site.baseurl }}">{{ post.title }}</a>
      </h2>
      {{ post.excerpt }}<a href="{{ post.url }}">Read more...</a>
    </li>
  {% endfor %}
</ul>

