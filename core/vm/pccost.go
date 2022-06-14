package vm

import (
	"fmt"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/holiman/uint256"
)

type PcCost types.PcCost

func newpccost() *PcCost {
	return &PcCost{Pc: make([]uint64, 0, 1024), Data: make([]*uint256.Int, 0, 1024)}
}

var GlobalPcCost *PcCost = newpccost()

func (st *PcCost) push(d *uint256.Int, p uint64) {
	// NOTE push limit (1024) is checked in baseCheck
	//stackItem := new(big.Int).Set(d)
	//st.data = append(st.data, stackItem)
	st.Data = append(st.Data, d)
	st.Pc = append(st.Pc, p)
}

func (st *PcCost) PrintCost() {
	fmt.Println("### cost stack ###")
	if len(st.Data) > 0 {
		for i, val := range st.Data {
			fmt.Printf("%d  %v\n", st.Pc[i], val)
		}
	} else {
		fmt.Println("-- empty --")
	}
	fmt.Println("#############")
}
