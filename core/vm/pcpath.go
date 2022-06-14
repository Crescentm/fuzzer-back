package vm

import (
	"fmt"

	"github.com/ethereum/go-ethereum/core/types"
)

type PcPath types.PcPath

func newpcstack() *PcPath {
	return &PcPath{Path: make([]int, 0, 1024)}
}

var GlobalPcPath *PcPath = newpcstack()

func (st *PcPath) Pushpath(d int) {
	// NOTE push limit (1024) is checked in baseCheck
	//stackItem := new(big.Int).Set(d)
	//st.data = append(st.data, stackItem)
	st.Path = append(st.Path, d)
}

func (st *PcPath) Print() {
	fmt.Println("### Track of PC ###")
	if len(st.Path) > 0 {
		for i, val := range st.Path {
			if i%2 == 0 {
				fmt.Printf("%dst jump source:", i/2+1)
			} else {
				fmt.Printf("%dst jump destination:", i/2+1)
			}

			fmt.Printf(" %v\n", val)
		}
	} else {
		fmt.Println("-- empty --")
	}
	fmt.Println("#############")
}
