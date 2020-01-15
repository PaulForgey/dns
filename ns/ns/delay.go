package main

import (
	"math/rand"
	"time"
)

// The Delay object allows events to be rate limited.
// Delay assumes Start, Stop, Fire, Reset are all called from one go routine at a time, usually the same one
type Delay struct {
	trigger bool
	t       *time.Timer
}

// Start queues the event. The channel in Fire will be readable after the time period since the first call to Start
func (d *Delay) Start() {
	d.trigger = true
	if d.t == nil {
		d.t = time.NewTimer(time.Duration(rand.Int()%5+5) * time.Second)
	}
}

// Stop releases the timer
func (d *Delay) Stop() {
	if d.t != nil {
		if !d.t.Stop() {
			<-d.t.C
		}
		d.t = nil
	}
}

// Fire returns a channel to wake up on after the time period if triggered, else nil
func (d *Delay) Fire() <-chan time.Time {
	if d.t == nil || !d.trigger {
		return nil
	}
	return d.t.C
}

// Reset marks the event as claimed. Only call after waking up on Fire, so the channel has known to have been drained
func (d *Delay) Reset() {
	d.trigger = false
	d.t.Reset(time.Duration(rand.Int()%5+5) * time.Second)
}
