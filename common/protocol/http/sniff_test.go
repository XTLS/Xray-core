package http_test

import (
	"context"
	"testing"

	. "github.com/xtls/xray-core/common/protocol/http"
)

func TestHTTPHeaders(t *testing.T) {
	cases := []struct {
		input  string
		domain string
		err    bool
	}{
		{
			input: "GET /tutorials/other/top-20-mysql-best-practices/ HTTP/1.1\r\n" +
				"Host: net.tutsplus.com\r\n" +
				"User-Agent: Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.5) Gecko/20091102 Firefox/3.5.5 (.NET CLR 3.5.30729)\r\n" +
				"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n" +
				"Accept-Language: en-us,en;q=0.5\r\n" +
				"Accept-Encoding: gzip,deflate\r\n" +
				"Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7\r\n" +
				"Keep-Alive: 300\r\n" +
				"Connection: keep-alive\r\n" +
				"Cookie: PHPSESSID=r2t5uvjq435r4q7ib3vtdjq120\r\n" +
				"Pragma: no-cache\r\n" +
				"Cache-Control: no-cache\r\n" +
				"\r\n",
			domain: "net.tutsplus.com",
		},
		{
			input: "POST /foo.php HTTP/1.1\r\n" +
				"Host: localhost\r\n" +
				"User-Agent: Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.5) Gecko/20091102 Firefox/3.5.5 (.NET CLR 3.5.30729)\r\n" +
				"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n" +
				"Accept-Language: en-us,en;q=0.5\r\n" +
				"Accept-Encoding: gzip,deflate\r\n" +
				"Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7\r\n" +
				"Keep-Alive: 300\r\n" +
				"Connection: keep-alive\r\n" +
				"Referer: http://localhost/test.php\r\n" +
				"Content-Type: application/x-www-form-urlencoded\r\n" +
				"Content-Length: 43\r\n" +
				"\r\n" +
				"first_name=John&last_name=Doe&action=Submit",
			domain: "localhost",
		},
		{
			input: "X /foo.php HTTP/1.1\r\n" +
				"Host: localhost\r\n" +
				"User-Agent: Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.5) Gecko/20091102 Firefox/3.5.5 (.NET CLR 3.5.30729)\r\n" +
				"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n" +
				"Accept-Language: en-us,en;q=0.5\r\n" +
				"Accept-Encoding: gzip,deflate\r\n" +
				"Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7\r\n" +
				"Keep-Alive: 300\r\n" +
				"Connection: keep-alive\r\n" +
				"Referer: http://localhost/test.php\r\n" +
				"Content-Type: application/x-www-form-urlencoded\r\n" +
				"Content-Length: 43\r\n" +
				"\r\n" +
				"first_name=John&last_name=Doe&action=Submit",
			domain: "",
			err:    true,
		},
		{
			input: "GET /foo.php HTTP/1.1\r\n" +
				"User-Agent: Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.5) Gecko/20091102 Firefox/3.5.5 (.NET CLR 3.5.30729)\r\n" +
				"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n" +
				"Accept-Language: en-us,en;q=0.5\r\n" +
				"Accept-Encoding: gzip,deflate\r\n" +
				"Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7\r\n" +
				"Keep-Alive: 300\r\n" +
				"Connection: keep-alive\r\n" +
				"Referer: http://localhost/test.php\r\n" +
				"Content-Type: application/x-www-form-urlencoded\r\n" +
				"Content-Length: 43\r\n" +
				"\r\n" +
				"Host: localhost\r\n" +
				"first_name=John&last_name=Doe&action=Submit",
			domain: "",
			err:    true,
		},
		{
			input:  "GET /tutorials/other/top-20-mysql-best-practices/ HTTP/1.1\r\n",
			domain: "",
			err:    true,
		},
	}

	for _, test := range cases {
		header, err := SniffHTTP([]byte(test.input), context.TODO())
		if test.err {
			if err == nil {
				t.Errorf("Expect error but nil, in test: %v", test)
			}
		} else {
			if err != nil {
				t.Errorf("Expect no error but actually %s in test %v", err.Error(), test)
				continue
			}
			if header.Domain() != test.domain {
				t.Error("expected domain ", test.domain, " but got ", header.Domain())
			}
		}
	}
}
