# vhl.ink

Custom link shortener service using Cloudflare Workers + KV store on your domain. The Workers free tier is quite generous and perfectly suited for this since KV is optimized for high reads and infrequent writes, which is our use case. 
  
This fork removes useless endpoints, and replaces x-preshared-key header with "proper" HTTP Basic authentication (username is not verified, but could allow for client identification later on);  

See original README here: [vhl.ink](https://github.com/VandyHacks/vhl.ink).