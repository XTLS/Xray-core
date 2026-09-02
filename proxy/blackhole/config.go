package blackhole

var http403response = []byte(`HTTP/1.1 403 Forbidden
Connection: close
Cache-Control: max-age=3600, public
Content-Length: 0


`)
