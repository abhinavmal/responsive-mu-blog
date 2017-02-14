# Responsive - Multi User Blog

This is the source code for a multi-user blog, hosted with the Google App Engine (GAE) at 

  https://mu-blog-5551.appspot.com/.

- The blog allows users to create secure accounts (hashed passwords, secure cookies).

- Users can let their heart out without really the fear of disclosing their identity, it is an emotional outlet after a long day of work/play/study/fun!

- Users can like/dislike and comment on other's posts (ONLY).

- The blog is responsive and has customized CSS to handle its rendering on both Desktop and Mobile Devices. Tested on Nexus 5.

- Dependencies:

  * Frontend
    - jQuery
    - Bootstrap Framework
    - Fontawesome
    - Google Fonts
        - Headings and Post Title: Pathway Gothic One
        - Posts: Source Serif Pro
        - Comment Title: Roboto
        - Comment Content: Goudy Bookletter 1911

  * Backend
    - Jinja2 for templating
    - GAE Framework
    - NDB datastore
    - Hashlib and hmac for hashing
    - gae-pytz for setting correct date and time zone, for posts and comments
