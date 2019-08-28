package oioidwsrest


type SessionStore struct {

}


func NewSessionStore() *SessionStore {
	s := new(SessionStore)
	return s
}

type Session struct {

}

func (s SessionStore) GetValidSessionFromId(sessionId string) (*Session, error) {
	
	session := new(Session)
	return session, nil
}
