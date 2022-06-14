package vm

import (
	"fmt"
	"math/big"
)

type CostStack struct {
	pc   []uint64
	data []*big.Int
}

func newcoststack() *CostStack {
	return &CostStack{pc: make([]uint64, 0, 1024), data: make([]*big.Int, 0, 1024)}
}

var cost = newcoststack()

func (st *CostStack) push(d *big.Int, p uint64) {
	// NOTE push limit (1024) is checked in baseCheck
	//stackItem := new(big.Int).Set(d)
	//st.data = append(st.data, stackItem)
	st.data = append(st.data, d)
	st.pc = append(st.pc, p)
}

func (st *CostStack) PrintCost() {
	fmt.Println("### cost stack ###")
	if len(st.data) > 0 {
		for i, val := range st.data {
			fmt.Printf("%d  %v\n", st.pc[i], val)
		}
	} else {
		fmt.Println("-- empty --")
	}
	fmt.Println("#############")
}
