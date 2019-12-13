package tcp

// Token is used as a permission to keep on running.
type Token struct {
}

// TokenLimiter is used to limit the number of concurrent tasks.
type TokenLimiter struct {
	count uint
	ch    chan *Token
}

// Put releases the token.
func (tl *TokenLimiter) Put(tk *Token) {
	tl.ch <- tk
}

// Get obtains a token.
func (tl *TokenLimiter) Get() *Token {
	return <-tl.ch
}

// NewTokenLimiter creates a TokenLimiter with count tokens.
func NewTokenLimiter(count uint) *TokenLimiter {
	tl := &TokenLimiter{count: count, ch: make(chan *Token, count)}
	for i := uint(0); i < count; i++ {
		tl.ch <- &Token{}
	}

	return tl
}
