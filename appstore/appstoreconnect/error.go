package appstoreconnect

import "strconv"

type ErrHTTP struct {
	Status       int
	ResponseBody string
}

func (s *ErrHTTP) Error() string {
	return "bad http response: " + strconv.Itoa(s.Status) + " : body: " + s.ResponseBody
}
