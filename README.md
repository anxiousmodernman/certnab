# certnab

Simple Let's Encrypt client.

## Usage

This is a standalone binary that performs the ACME protocol's HTTP-based 
challenge against an ACME server. By default, certnab uses the Let's Encrypt
**staging** endpoint. This allows you to test connectivity before hitting prod. 
If you want to get "real" certs, you must pass the production URL (Dec 2017: 
acme-v01.api.letsencrypt.org) with the `--acme-server` flag.

For example

```
certnab renew --acme-server=acme-v01.api.letsencrypt.org --domain=example.com --dest=$(pwd)
```

If all goes well, you can inspect the resulting cert like this

```
cat cert.pem | openssl x509 -text
```

Important notes:

* certnab spins up a temporary server that binds to port 80, and so it will
  probably need to run as root
* No other server can be bound to port 80 while certnab runs (it should only 
  take a few seconds to run)
* Completing this challenge requires DNS to point at the IP where certnab runs
* Let's Encrypt has very strict rate limits, and they'll lock you out for days
  if you exceed your limit. Test against their staging server first!
* This ACME challenge scheme will likely involve a little bit of downtime, but
  is also simple and effective. 



