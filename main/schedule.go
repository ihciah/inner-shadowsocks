package main

import (
	"sync"
	"time"
	"log"
)

type Scheduler struct{
	max_fail int
	status []bool
	fail_count []int
	succ_chan chan int
	fail_chan chan int
	lock sync.Mutex
	verbose bool
}

func (s *Scheduler)log(f string, v ...interface{}) {
	if s.verbose {
		log.Printf(f, v...)
	}
}

func (s *Scheduler) get() int{
	for i, v := range(s.status){
		if v{
			s.log("[Schedule] Get server %d.", i)
			return i
		}
	}
	s.lock.Lock()
	for i := range(s.status){
		s.status[i] = true
		s.fail_count[i] = 0
	}
	s.lock.Unlock()
	s.log("[Schedule] All servers down. Restart all of them. Get 0")
	return 0
}

func (s *Scheduler) report_success(id int){
	s.log("[Schedule] %d success.", id)
	s.succ_chan <- id
}

func (s *Scheduler) report_fail(id int){
	s.log("[Schedule] %d fail.", id)
	s.fail_chan <- id
}

func (s *Scheduler) init(n, max_fail, chan_buf, recover_time int, verbose bool){
	s.verbose = verbose
	s.max_fail = max_fail
	s.status = make([]bool, n)
	for i := range(s.status){
		s.status[i] = true
	}
	s.fail_count = make([]int, n)
	s.succ_chan, s.fail_chan = make(chan int, chan_buf), make(chan int, chan_buf)
	go s.process(recover_time)
	s.log("[Schedule] Init. Maxfail=%d, Recover_time=%d sec, channel_buffer_size=%d", max_fail, recover_time, chan_buf)
}

func (s *Scheduler) process(recover_time int){
	for {
		select {
		case succ := <-s.succ_chan:
			s.lock.Lock()
			s.status[succ] = true
			s.fail_count[succ] = 0
			s.lock.Unlock()
		case fail := <-s.fail_chan:
			s.lock.Lock()
			if s.status[fail] == true{
				if s.fail_count[fail] >= s.max_fail {
					s.fail_count[fail] = 0
					s.status[fail] = false
					go func(locker *sync.Mutex, timer *time.Timer) {
						<-timer.C
						locker.Lock()
						s.status[fail] = true
						s.fail_count[fail] = 0
						locker.Unlock()
						s.log("[Schedule] Server %d up due to time exceed.", fail)
					}(&s.lock, time.NewTimer(time.Second * time.Duration(recover_time)))
					s.log("[Schedule] Server %d down.", fail)
				} else{
					s.fail_count[fail]++
					s.log("[Schedule] %d fail count: %d.", fail, s.fail_count[fail])
				}
			}
			s.lock.Unlock()
		}
	}
}
//
//func main(){
//	var S Scheduler
//	var x int
//	S.init(5, 3, 100)
//
//	for i:=0;i<60;i++{
//		x = S.get()
//		fmt.Println(x)
//		S.report_fail(x)
//		time.Sleep(time.Second)
//	}
//}