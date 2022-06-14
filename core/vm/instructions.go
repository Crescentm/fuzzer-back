// Copyright 2015 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package vm

import (
	"math/big"
	"sync/atomic"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/params"
	"github.com/holiman/uint256"
	"golang.org/x/crypto/sha3"
)

func checkAddProtection(pc *uint64, contract *Contract) bool {
	var n = *pc
	var op OpCode
	//fmt.Println(contract.GetOp(n))
	for {
		op = contract.GetOp(n)
		if op == JUMP || op == JUMPI || op == JUMPDEST {
			break
		}
		if op == CREATE || op == CALL || op == CALLCODE || op == RETURN || op == DELEGATECALL || op == STATICCALL || op == REVERT || op == SELFDESTRUCT {
			break
		}

		// safemath pattern: contract3.safeadd1
		// assert(c >= a)
		if op == DUP4 && contract.GetOp(n+1) == DUP2 && contract.GetOp(n+2) == LT && contract.GetOp(n+3) == ISZERO {
			return true
		}

		// safemath pattern: contract3.safeadd2
		// if(a + b >= a)
		if op == ADD && contract.GetOp(n+1) == LT && contract.GetOp(n+2) == ISZERO {
			return true
		}
		if op == ADD && contract.GetOp(n+1) == GT && contract.GetOp(n+2) == JUMPDEST && contract.GetOp(n+3) == ISZERO {
			return true
		}

		n++
	}

	n = *pc
	for {
		op = contract.GetOp(n)
		if op == JUMP || op == JUMPI || op == JUMPDEST {
			break
		}
		if op == CREATE || op == CALL || op == CALLCODE || op == RETURN || op == DELEGATECALL || op == STATICCALL || op == REVERT || op == SELFDESTRUCT {
			break
		}

		// safemath pattern: contract3.safeadd2
		// if(a + b >= a)
		if op == ADD && contract.GetOp(n+1) == LT && contract.GetOp(n+2) == ISZERO {
			return true
		}

		// safemath pattern: contract3.safeadd3
		// if (a > MAX_UINT256 - b) throw;
		if op == ADD && contract.GetOp(n-15) == SUB && contract.GetOp(n-14) == DUP4 && contract.GetOp(n-13) == GT && contract.GetOp(n-12) == ISZERO {
			return true
		}

		n--
	}
	return false
}

func checkSubProtection(pc *uint64, contract *Contract) bool {
	var n = *pc
	var op OpCode
	//fmt.Println(contract.GetOp(n))

	n = *pc
	for {
		op = contract.GetOp(n)
		if op == JUMP || op == JUMPI || op == JUMPDEST {
			break
		}
		if op == CREATE || op == CALL || op == CALLCODE || op == RETURN || op == DELEGATECALL || op == STATICCALL || op == REVERT || op == SELFDESTRUCT {
			break
		}

		// safemath pattern: contract4.safesub1
		// assert(b<=a)
		if op == SUB && contract.GetOp(n-14) == DUP3 && contract.GetOp(n-13) == DUP3 && contract.GetOp(n-12) == GT && contract.GetOp(n-11) == ISZERO {
			return true
		}

		// safemath pattern: contract4.safesub2
		// if(a>=b)
		if op == SUB && contract.GetOp(n-11) == DUP2 && contract.GetOp(n-10) == DUP4 && contract.GetOp(n-9) == LT && contract.GetOp(n-8) == ISZERO {
			return true
		}

		// safemath pattern: contract4.safesub2
		// if (a < b) throw;
		if op == SUB && contract.GetOp(n-15) == DUP2 && contract.GetOp(n-14) == DUP4 && contract.GetOp(n-13) == LT && contract.GetOp(n-12) == ISZERO {
			return true
		}

		n--
	}
	return false
}

func checkMulProtection(pc *uint64, contract *Contract) bool {
	var n = *pc
	var op OpCode
	//fmt.Println(contract.GetOp(n))
	for {
		op = contract.GetOp(n)
		if op == JUMP || op == JUMPI || op == JUMPDEST {
			break
		}
		if op == CREATE || op == CALL || op == CALLCODE || op == RETURN || op == DELEGATECALL || op == STATICCALL || op == REVERT || op == SELFDESTRUCT {
			break
		}

		// safemath pattern: contract5.safemul1
		// assert(a == 0 || c / a == b);
		if op == PUSH1 && contract.GetOp(n+2) == DUP5 && contract.GetOp(n+3) == EQ && contract.GetOp(n+22) == DIV && contract.GetOp(n+23) == EQ {
			return true
		}

		n++
	}

	n = *pc
	for {
		op = contract.GetOp(n)
		if op == JUMP || op == JUMPI || op == JUMPDEST {
			break
		}
		if op == CREATE || op == CALL || op == CALLCODE || op == RETURN || op == DELEGATECALL || op == STATICCALL || op == REVERT || op == SELFDESTRUCT {
			break
		}

		// safemath pattern: contract5.safemul2
		// if (x > MAX_UINT256 / y) throw;
		if op == MUL && contract.GetOp(n-15) == DIV && contract.GetOp(n-14) == DUP4 && contract.GetOp(n-13) == GT && contract.GetOp(n-12) == ISZERO {
			return true
		}

		n--
	}
	return false
}

func opAdd(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error, []int, PcPath, PcCost) {
	x, y := scope.Stack.pop(), scope.Stack.peek()
	temp_x := x
	temp_y := y
	y.Add(&x, y)
	temp_res := y
	temp_flag := SAFE_FLAG
	tx, ty := scope.TaintStack.pop(), scope.TaintStack.pop()
	if (tx|ty)&CALLDATA_FLAG > 0 {
		if temp_res.Lt(&temp_x) || temp_res.Lt(temp_y) {
			if checkAddProtection(pc, scope.Contract) {
				temp_flag |= PROTECTED_OVERFLOW_FLAG
				global_taint_flag |= PROTECTED_OVERFLOW_FLAG
			} else {
				temp_flag |= OVERFLOW_FLAG
				global_taint_flag |= OVERFLOW_FLAG
			}
		}
		temp_flag |= POTENTIAL_OVERFLOW_FLAG
		global_taint_flag |= POTENTIAL_OVERFLOW_FLAG
	}

	scope.TaintStack.push(temp_flag)
	return nil, nil, nil, PcPath{}, PcCost{}
}

func opSub(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error, []int, PcPath, PcCost) {
	x, y := scope.Stack.pop(), scope.Stack.peek()
	temp_x := x
	temp_y := y
	temp_flag := SAFE_FLAG

	tx, ty := scope.TaintStack.pop(), scope.TaintStack.pop()
	if (tx|ty)&CALLDATA_FLAG > 0 {
		if temp_y.Gt(&temp_x) {
			if checkSubProtection(pc, scope.Contract) {
				temp_flag |= PROTECTED_OVERFLOW_FLAG
				global_taint_flag |= PROTECTED_OVERFLOW_FLAG
			} else {
				temp_flag |= OVERFLOW_FLAG
				global_taint_flag |= OVERFLOW_FLAG
			}
		}
		temp_flag |= POTENTIAL_OVERFLOW_FLAG
		global_taint_flag |= POTENTIAL_OVERFLOW_FLAG
	}

	scope.TaintStack.push(temp_flag)

	y.Sub(&x, y)
	return nil, nil, nil, PcPath{}, PcCost{}
}

func opMul(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error, []int, PcPath, PcCost) {
	x, y := scope.Stack.pop(), scope.Stack.peek()
	temp_x := x
	temp_y := y
	y.Mul(&x, y)
	temp_res := y
	temp_flag := SAFE_FLAG
	tx, ty := scope.TaintStack.pop(), scope.TaintStack.pop()

	if (tx|ty)&CALLDATA_FLAG > 0 {
		if temp_x.Cmp(uint256.NewInt(0)) != 0 && temp_res.Div(temp_res, &temp_x).Cmp(temp_y) != 0 {
			if checkMulProtection(pc, scope.Contract) {
				temp_flag |= PROTECTED_OVERFLOW_FLAG
				global_taint_flag |= PROTECTED_OVERFLOW_FLAG
			} else {
				temp_flag |= OVERFLOW_FLAG
				global_taint_flag |= OVERFLOW_FLAG
			}
		}
		temp_flag |= POTENTIAL_OVERFLOW_FLAG
		global_taint_flag |= POTENTIAL_OVERFLOW_FLAG
	}

	scope.TaintStack.push(temp_flag)
	return nil, nil, nil, PcPath{}, PcCost{}
}

func opDiv(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error, []int, PcPath, PcCost) {
	x, y := scope.Stack.pop(), scope.Stack.peek()
	y.Div(&x, y)
	tx, ty := scope.TaintStack.pop(), scope.TaintStack.pop()
	scope.TaintStack.push(tx | ty)
	return nil, nil, nil, PcPath{}, PcCost{}
}

func opSdiv(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error, []int, PcPath, PcCost) {
	x, y := scope.Stack.pop(), scope.Stack.peek()
	y.SDiv(&x, y)
	tx, ty := scope.TaintStack.pop(), scope.TaintStack.pop()
	scope.TaintStack.push(tx | ty)
	return nil, nil, nil, PcPath{}, PcCost{}
}

func opMod(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error, []int, PcPath, PcCost) {
	x, y := scope.Stack.pop(), scope.Stack.peek()
	y.Mod(&x, y)
	tx, ty := scope.TaintStack.pop(), scope.TaintStack.pop()
	scope.TaintStack.push(tx | ty)
	return nil, nil, nil, PcPath{}, PcCost{}
}

func opSmod(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error, []int, PcPath, PcCost) {
	x, y := scope.Stack.pop(), scope.Stack.peek()
	y.SMod(&x, y)
	tx, ty := scope.TaintStack.pop(), scope.TaintStack.pop()
	scope.TaintStack.push(tx | ty)
	return nil, nil, nil, PcPath{}, PcCost{}
}

func opExp(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error, []int, PcPath, PcCost) {
	base, exponent := scope.Stack.pop(), scope.Stack.peek()
	exponent.Exp(&base, exponent)
	return nil, nil, nil, PcPath{}, PcCost{}
}

func opSignExtend(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error, []int, PcPath, PcCost) {
	back, num := scope.Stack.pop(), scope.Stack.peek()
	num.ExtendSign(num, &back)
	return nil, nil, nil, PcPath{}, PcCost{}
}

func opNot(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error, []int, PcPath, PcCost) {
	x := scope.Stack.peek()
	x.Not(x)
	return nil, nil, nil, PcPath{}, PcCost{}
}

func opLt(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error, []int, PcPath, PcCost) {
	x, y := scope.Stack.pop(), scope.Stack.peek()
	tx, ty := scope.TaintStack.pop(), scope.TaintStack.pop()
	left := new(uint256.Int).Set(&x)
	right := new(uint256.Int).Set(y)
	if x.Lt(y) {
		if (tx|ty)&CALLDATA_FLAG > 0 {
			var res1 *uint256.Int = new(uint256.Int)
			var res2 *uint256.Int = new(uint256.Int)
			res1.Sub(right, left)
			res1.Abs(res1)
			res2 = uint256.NewInt(0)

			GlobalPcCost.push(res1, *pc)
			GlobalPcCost.push(res2, *pc)
		}
		y.SetOne()
	} else {
		if (tx|ty)&CALLDATA_FLAG > 0 {
			var res1 *uint256.Int = new(uint256.Int)
			var res2 *uint256.Int = new(uint256.Int)

			res1 = uint256.NewInt(0)
			res2.Sub(left, right)
			res2.Add(res2, uint256.NewInt(1))
			res2.Abs(res2)

			GlobalPcCost.push(res1, *pc)
			GlobalPcCost.push(res2, *pc)
		}
		y.Clear()
	}

	var n = *pc
	op := scope.Contract.GetOp(n)
	if op == PUSH1 && scope.Contract.GetOp(n+2) == JUMPI {
		global_branch_flag |= BRANCH_FLAG
	}

	scope.TaintStack.push(tx | ty)
	return nil, nil, nil, PcPath{}, PcCost{}
}

func opGt(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error, []int, PcPath, PcCost) {
	x, y := scope.Stack.pop(), scope.Stack.peek()
	tx, ty := scope.TaintStack.pop(), scope.TaintStack.pop()
	left := new(uint256.Int).Set(&x)
	right := new(uint256.Int).Set(y)
	if x.Gt(y) {
		if (tx|ty)&CALLDATA_FLAG > 0 {
			var res1 *uint256.Int = new(uint256.Int)
			var res2 *uint256.Int = new(uint256.Int)
			res1.Sub(left, right)
			res1.Abs(res1)
			res2 = uint256.NewInt(0)

			GlobalPcCost.push(res1, *pc)
			GlobalPcCost.push(res2, *pc)
		}
		y.SetOne()
	} else {
		if (tx|ty)&CALLDATA_FLAG > 0 {
			var res1 *uint256.Int = new(uint256.Int)
			var res2 *uint256.Int = new(uint256.Int)

			res1 = uint256.NewInt(0)
			res2.Sub(right, left)
			res2.Add(res2, uint256.NewInt(1))
			res2.Abs(res2)

			GlobalPcCost.push(res1, *pc)
			GlobalPcCost.push(res2, *pc)
		}
		y.Clear()
	}

	var n = *pc
	op := scope.Contract.GetOp(n)
	if op == PUSH1 && scope.Contract.GetOp(n+2) == JUMPI {
		global_branch_flag |= BRANCH_FLAG
	}

	scope.TaintStack.push(tx | ty)
	return nil, nil, nil, PcPath{}, PcCost{}
}

func opSlt(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error, []int, PcPath, PcCost) {
	x, y := scope.Stack.pop(), scope.Stack.peek()
	if x.Slt(y) {
		y.SetOne()
	} else {
		y.Clear()
	}
	return nil, nil, nil, PcPath{}, PcCost{}
}

func opSgt(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error, []int, PcPath, PcCost) {
	x, y := scope.Stack.pop(), scope.Stack.peek()
	if x.Sgt(y) {
		y.SetOne()
	} else {
		y.Clear()
	}
	return nil, nil, nil, PcPath{}, PcCost{}
}

func opEq(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error, []int, PcPath, PcCost) {
	x, y := scope.Stack.pop(), scope.Stack.peek()
	left := new(uint256.Int).Set(&x)
	right := new(uint256.Int).Set(y)

	tx, ty := scope.TaintStack.pop(), scope.TaintStack.pop()
	if x.Eq(y) {
		if (tx|ty)&CALLDATA_FLAG > 0 {
			var res1 *uint256.Int
			var res2 *uint256.Int

			res1 = uint256.NewInt(1)
			res2 = uint256.NewInt(0)
			GlobalPcCost.push(res1, *pc)
			GlobalPcCost.push(res2, *pc)
		}

		y.SetOne()
	} else {
		if (tx|ty)&CALLDATA_FLAG > 0 {
			var res1 *uint256.Int
			var res2 *uint256.Int
			res1 = uint256.NewInt(0)
			var tmp *uint256.Int = new(uint256.Int)

			tmp.Sub(left, right)
			if tmp.Cmp(uint256.NewInt(0)) < 0 {
				res2.Sub(uint256.NewInt(0), tmp)
			} else {
				res2 = tmp
			}
			res2.Abs(res2)
			GlobalPcCost.push(res1, *pc)
			GlobalPcCost.push(res2, *pc)
		}

		y.Clear()
	}
	var n = *pc
	op := scope.Contract.GetOp(n)
	if op == PUSH1 && scope.Contract.GetOp(n+2) == JUMPI {
		global_branch_flag |= BRANCH_FLAG
	}

	scope.TaintStack.push(tx | ty)
	return nil, nil, nil, PcPath{}, PcCost{}
}

func opIszero(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error, []int, PcPath, PcCost) {
	x := scope.Stack.peek()
	if x.IsZero() {
		x.SetOne()
	} else {
		x.Clear()
	}
	return nil, nil, nil, PcPath{}, PcCost{}
}

func opAnd(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error, []int, PcPath, PcCost) {
	x, y := scope.Stack.pop(), scope.Stack.peek()
	y.And(&x, y)
	tx, ty := scope.TaintStack.pop(), scope.TaintStack.pop()
	scope.TaintStack.push(tx | ty)
	return nil, nil, nil, PcPath{}, PcCost{}
}

func opOr(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error, []int, PcPath, PcCost) {
	x, y := scope.Stack.pop(), scope.Stack.peek()
	y.Or(&x, y)
	tx, ty := scope.TaintStack.pop(), scope.TaintStack.pop()
	scope.TaintStack.push(tx | ty)
	return nil, nil, nil, PcPath{}, PcCost{}
}

func opXor(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error, []int, PcPath, PcCost) {
	x, y := scope.Stack.pop(), scope.Stack.peek()
	y.Xor(&x, y)
	tx, ty := scope.TaintStack.pop(), scope.TaintStack.pop()
	scope.TaintStack.push(tx | ty)
	return nil, nil, nil, PcPath{}, PcCost{}
}

func opByte(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error, []int, PcPath, PcCost) {
	th, val := scope.Stack.pop(), scope.Stack.peek()
	val.Byte(&th)
	tx, ty := scope.TaintStack.pop(), scope.TaintStack.pop()
	scope.TaintStack.push(tx | ty)
	return nil, nil, nil, PcPath{}, PcCost{}
}

func opAddmod(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error, []int, PcPath, PcCost) {
	x, y, z := scope.Stack.pop(), scope.Stack.pop(), scope.Stack.peek()
	tx, ty, tz := scope.TaintStack.pop(), scope.TaintStack.pop(), scope.TaintStack.pop()
	temp_x := new(uint256.Int).Set(&x)
	temp_y := new(uint256.Int).Set(&y)
	if z.IsZero() {
		z.Clear()
		scope.TaintStack.push(tz)
	} else {
		z.AddMod(&x, &y, z)
		temp_flag := SAFE_FLAG
		temp_res := new(uint256.Int).Set(z)
		if (tx|ty)&CALLDATA_FLAG > 0 {
			if temp_res.Cmp(temp_x) < 0 || temp_res.Cmp(temp_y) < 0 {
				if checkAddProtection(pc, scope.Contract) {
					temp_flag |= PROTECTED_OVERFLOW_FLAG
					global_taint_flag |= PROTECTED_OVERFLOW_FLAG
				} else {
					temp_flag |= OVERFLOW_FLAG
					global_taint_flag |= OVERFLOW_FLAG
				}
			}
			temp_flag |= POTENTIAL_OVERFLOW_FLAG
			global_taint_flag |= POTENTIAL_OVERFLOW_FLAG
		}

		scope.TaintStack.push(temp_flag)
	}
	return nil, nil, nil, PcPath{}, PcCost{}
}

func opMulmod(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error, []int, PcPath, PcCost) {
	x, y, z := scope.Stack.pop(), scope.Stack.pop(), scope.Stack.peek()
	z.MulMod(&x, &y, z)
	return nil, nil, nil, PcPath{}, PcCost{}
}

// opSHL implements Shift Left
// The SHL instruction (shift left) pops 2 values from the stack, first arg1 and then arg2,
// and pushes on the stack arg2 shifted to the left by arg1 number of bits.
func opSHL(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error, []int, PcPath, PcCost) {
	// Note, second operand is left in the stack; accumulate result into it, and no need to push it afterwards
	shift, value := scope.Stack.pop(), scope.Stack.peek()
	tx, ty := scope.TaintStack.pop(), scope.TaintStack.pop()
	scope.TaintStack.push(tx | ty)
	if shift.LtUint64(256) {
		value.Lsh(value, uint(shift.Uint64()))
	} else {
		value.Clear()
	}
	return nil, nil, nil, PcPath{}, PcCost{}
}

// opSHR implements Logical Shift Right
// The SHR instruction (logical shift right) pops 2 values from the stack, first arg1 and then arg2,
// and pushes on the stack arg2 shifted to the right by arg1 number of bits with zero fill.
func opSHR(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error, []int, PcPath, PcCost) {
	// Note, second operand is left in the stack; accumulate result into it, and no need to push it afterwards
	shift, value := scope.Stack.pop(), scope.Stack.peek()
	tx, ty := scope.TaintStack.pop(), scope.TaintStack.pop()
	scope.TaintStack.push(tx | ty)
	if shift.LtUint64(256) {
		value.Rsh(value, uint(shift.Uint64()))
	} else {
		value.Clear()
	}
	return nil, nil, nil, PcPath{}, PcCost{}
}

// opSAR implements Arithmetic Shift Right
// The SAR instruction (arithmetic shift right) pops 2 values from the stack, first arg1 and then arg2,
// and pushes on the stack arg2 shifted to the right by arg1 number of bits with sign extension.
func opSAR(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error, []int, PcPath, PcCost) {
	shift, value := scope.Stack.pop(), scope.Stack.peek()
	tx, ty := scope.TaintStack.pop(), scope.TaintStack.pop()
	scope.TaintStack.push(tx | ty)
	if shift.GtUint64(256) {
		if value.Sign() >= 0 {
			value.Clear()
		} else {
			// Max negative shift: all bits set
			value.SetAllOne()
		}
		return nil, nil, nil, PcPath{}, PcCost{}
	}
	n := uint(shift.Uint64())
	value.SRsh(value, n)
	return nil, nil, nil, PcPath{}, PcCost{}
}

func opKeccak256(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error, []int, PcPath, PcCost) {
	offset, size := scope.Stack.pop(), scope.Stack.peek()
	data := scope.Memory.GetPtr(int64(offset.Uint64()), int64(size.Uint64()))

	if interpreter.hasher == nil {
		interpreter.hasher = sha3.NewLegacyKeccak256().(keccakState)
	} else {
		interpreter.hasher.Reset()
	}
	interpreter.hasher.Write(data)
	interpreter.hasher.Read(interpreter.hasherBuf[:])

	evm := interpreter.evm
	if evm.Config.EnablePreimageRecording {
		evm.StateDB.AddPreimage(interpreter.hasherBuf, data)
	}

	size.SetBytes(interpreter.hasherBuf[:])
	return nil, nil, nil, PcPath{}, PcCost{}
}
func opAddress(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error, []int, PcPath, PcCost) {
	scope.Stack.push(new(uint256.Int).SetBytes(scope.Contract.Address().Bytes()))
	scope.TaintStack.push(SAFE_FLAG)
	return nil, nil, nil, PcPath{}, PcCost{}
}

func opBalance(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error, []int, PcPath, PcCost) {
	slot := scope.Stack.peek()
	address := common.Address(slot.Bytes20())
	slot.SetFromBig(interpreter.evm.StateDB.GetBalance(address))
	return nil, nil, nil, PcPath{}, PcCost{}
}

func opOrigin(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error, []int, PcPath, PcCost) {
	scope.Stack.push(new(uint256.Int).SetBytes(interpreter.evm.Origin.Bytes()))
	scope.TaintStack.push(SAFE_FLAG)

	return nil, nil, nil, PcPath{}, PcCost{}
}
func opCaller(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error, []int, PcPath, PcCost) {
	scope.Stack.push(new(uint256.Int).SetBytes(scope.Contract.Caller().Bytes()))
	scope.TaintStack.push(SAFE_FLAG)

	return nil, nil, nil, PcPath{}, PcCost{}
}

func opCallValue(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error, []int, PcPath, PcCost) {
	v, _ := uint256.FromBig(scope.Contract.value)
	scope.Stack.push(v)
	scope.TaintStack.push(CALLDATA_FLAG)

	return nil, nil, nil, PcPath{}, PcCost{}
}

func opCallDataLoad(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error, []int, PcPath, PcCost) {
	x := scope.Stack.peek()
	if offset, overflow := x.Uint64WithOverflow(); !overflow {
		data := getData(scope.Contract.Input, offset, 32)
		x.SetBytes(data)
	} else {
		x.Clear()
	}
	scope.TaintStack.pop()
	if *pc == 14 {
		// func selection
		scope.TaintStack.push(SAFE_FLAG)
	} else {
		scope.TaintStack.push(CALLDATA_FLAG)
	}
	return nil, nil, nil, PcPath{}, PcCost{}
}

func opCallDataSize(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error, []int, PcPath, PcCost) {
	scope.Stack.push(new(uint256.Int).SetUint64(uint64(len(scope.Contract.Input))))
	scope.TaintStack.push(SAFE_FLAG)
	return nil, nil, nil, PcPath{}, PcCost{}
}

func opCallDataCopy(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error, []int, PcPath, PcCost) {
	var (
		memOffset  = scope.Stack.pop()
		dataOffset = scope.Stack.pop()
		length     = scope.Stack.pop()
	)
	dataOffset64, overflow := dataOffset.Uint64WithOverflow()
	if overflow {
		dataOffset64 = 0xffffffffffffffff
	}
	// These values are checked for overflow during gas cost calculation
	memOffset64 := memOffset.Uint64()
	length64 := length.Uint64()
	scope.Memory.Set(memOffset64, length64, getData(scope.Contract.Input, dataOffset64, length64))

	var t_value []int
	for i := uint64(0); i < length64; i++ {
		t_value = append(t_value, CALLDATA_FLAG)
	}
	return nil, nil, nil, PcPath{}, PcCost{}
}

func opReturnDataSize(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error, []int, PcPath, PcCost) {
	scope.Stack.push(new(uint256.Int).SetUint64(uint64(len(interpreter.returnData))))
	scope.TaintStack.push(SAFE_FLAG)

	return nil, nil, nil, PcPath{}, PcCost{}
}

func opReturnDataCopy(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error, []int, PcPath, PcCost) {
	var (
		memOffset  = scope.Stack.pop()
		dataOffset = scope.Stack.pop()
		length     = scope.Stack.pop()
	)

	offset64, overflow := dataOffset.Uint64WithOverflow()
	if overflow {
		return nil, ErrReturnDataOutOfBounds, nil, PcPath{}, PcCost{}
	}
	// we can reuse dataOffset now (aliasing it for clarity)
	var end = dataOffset
	end.Add(&dataOffset, &length)
	end64, overflow := end.Uint64WithOverflow()
	if overflow || uint64(len(interpreter.returnData)) < end64 {
		return nil, ErrReturnDataOutOfBounds, nil, PcPath{}, PcCost{}
	}
	scope.Memory.Set(memOffset.Uint64(), length.Uint64(), interpreter.returnData[offset64:end64])
	scope.TaintMemory.Set(memOffset.Uint64(), length.Uint64(), interpreter.returnFlag[dataOffset.Uint64():end.Uint64()])

	return nil, nil, nil, PcPath{}, PcCost{}
}

func opExtCodeSize(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error, []int, PcPath, PcCost) {
	slot := scope.Stack.peek()
	slot.SetUint64(uint64(interpreter.evm.StateDB.GetCodeSize(slot.Bytes20())))
	scope.TaintStack.pop()
	scope.TaintStack.push(SAFE_FLAG)
	return nil, nil, nil, PcPath{}, PcCost{}
}

func opCodeSize(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error, []int, PcPath, PcCost) {
	l := new(uint256.Int)
	l.SetUint64(uint64(len(scope.Contract.Code)))
	scope.Stack.push(l)
	scope.TaintStack.push(SAFE_FLAG)

	return nil, nil, nil, PcPath{}, PcCost{}
}

func opCodeCopy(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error, []int, PcPath, PcCost) {
	var (
		memOffset  = scope.Stack.pop()
		codeOffset = scope.Stack.pop()
		length     = scope.Stack.pop()
	)
	uint64CodeOffset, overflow := codeOffset.Uint64WithOverflow()
	if overflow {
		uint64CodeOffset = 0xffffffffffffffff
	}
	codeCopy := getData(scope.Contract.Code, uint64CodeOffset, length.Uint64())
	scope.Memory.Set(memOffset.Uint64(), length.Uint64(), codeCopy)
	var t_value []int
	for i := uint64(0); i < length.Uint64(); i++ {
		t_value = append(t_value, SAFE_FLAG)
	}
	scope.TaintMemory.Set(memOffset.Uint64(), length.Uint64(), t_value)
	return nil, nil, nil, PcPath{}, PcCost{}
}

func opExtCodeCopy(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error, []int, PcPath, PcCost) {
	var (
		stack      = scope.Stack
		a          = stack.pop()
		memOffset  = stack.pop()
		codeOffset = stack.pop()
		length     = stack.pop()
	)
	uint64CodeOffset, overflow := codeOffset.Uint64WithOverflow()
	if overflow {
		uint64CodeOffset = 0xffffffffffffffff
	}
	addr := common.Address(a.Bytes20())
	codeCopy := getData(interpreter.evm.StateDB.GetCode(addr), uint64CodeOffset, length.Uint64())
	scope.Memory.Set(memOffset.Uint64(), length.Uint64(), codeCopy)
	var t_value []int
	for i := uint64(0); i < length.Uint64(); i++ {
		t_value = append(t_value, SAFE_FLAG)
	}
	scope.TaintMemory.Set(memOffset.Uint64(), length.Uint64(), t_value)
	return nil, nil, nil, PcPath{}, PcCost{}
}

// opExtCodeHash returns the code hash of a specified account.
// There are several cases when the function is called, while we can relay everything
// to `state.GetCodeHash` function to ensure the correctness.
//   (1) Caller tries to get the code hash of a normal contract account, state
// should return the relative code hash and set it as the result.
//
//   (2) Caller tries to get the code hash of a non-existent account, state should
// return common.Hash{} and zero will be set as the result.
//
//   (3) Caller tries to get the code hash for an account without contract code,
// state should return emptyCodeHash(0xc5d246...) as the result.
//
//   (4) Caller tries to get the code hash of a precompiled account, the result
// should be zero or emptyCodeHash.
//
// It is worth noting that in order to avoid unnecessary create and clean,
// all precompile accounts on mainnet have been transferred 1 wei, so the return
// here should be emptyCodeHash.
// If the precompile account is not transferred any amount on a private or
// customized chain, the return value will be zero.
//
//   (5) Caller tries to get the code hash for an account which is marked as suicided
// in the current transaction, the code hash of this account should be returned.
//
//   (6) Caller tries to get the code hash for an account which is marked as deleted,
// this account should be regarded as a non-existent account and zero should be returned.
func opExtCodeHash(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error, []int, PcPath, PcCost) {
	slot := scope.Stack.peek()
	address := common.Address(slot.Bytes20())
	if interpreter.evm.StateDB.Empty(address) {
		slot.Clear()
	} else {
		slot.SetBytes(interpreter.evm.StateDB.GetCodeHash(address).Bytes())
	}
	return nil, nil, nil, PcPath{}, PcCost{}
}

func opGasprice(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error, []int, PcPath, PcCost) {
	v, _ := uint256.FromBig(interpreter.evm.GasPrice)
	scope.Stack.push(v)
	scope.TaintStack.push(SAFE_FLAG)

	return nil, nil, nil, PcPath{}, PcCost{}
}

func opBlockhash(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error, []int, PcPath, PcCost) {
	num := scope.Stack.peek()
	t_num := scope.TaintStack.pop()

	num64, overflow := num.Uint64WithOverflow()
	if overflow {
		num.Clear()
		scope.TaintStack.push(0)
		return nil, nil, nil, PcPath{}, PcCost{}
	}
	var upper, lower uint64
	upper = interpreter.evm.Context.BlockNumber.Uint64()
	if upper < 257 {
		lower = 0
	} else {
		lower = upper - 256
	}
	if num64 >= lower && num64 < upper {
		num.SetBytes(interpreter.evm.Context.GetHash(num64).Bytes())
		scope.TaintStack.push(t_num)
	} else {
		num.Clear()
		scope.TaintStack.push(0)
	}
	return nil, nil, nil, PcPath{}, PcCost{}
}

func opCoinbase(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error, []int, PcPath, PcCost) {
	scope.Stack.push(new(uint256.Int).SetBytes(interpreter.evm.Context.Coinbase.Bytes()))
	scope.TaintStack.push(SAFE_FLAG)
	return nil, nil, nil, PcPath{}, PcCost{}
}

func opTimestamp(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error, []int, PcPath, PcCost) {
	v, _ := uint256.FromBig(interpreter.evm.Context.Time)
	scope.Stack.push(v)
	scope.TaintStack.push(SAFE_FLAG)

	return nil, nil, nil, PcPath{}, PcCost{}
}

func opNumber(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error, []int, PcPath, PcCost) {
	v, _ := uint256.FromBig(interpreter.evm.Context.BlockNumber)
	scope.Stack.push(v)
	scope.TaintStack.push(SAFE_FLAG)

	return nil, nil, nil, PcPath{}, PcCost{}
}

func opDifficulty(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error, []int, PcPath, PcCost) {
	v, _ := uint256.FromBig(interpreter.evm.Context.Difficulty)
	scope.Stack.push(v)
	scope.TaintStack.push(SAFE_FLAG)

	return nil, nil, nil, PcPath{}, PcCost{}
}

func opRandom(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error, []int, PcPath, PcCost) {
	v := new(uint256.Int).SetBytes(interpreter.evm.Context.Random.Bytes())
	scope.Stack.push(v)
	scope.TaintStack.push(SAFE_FLAG)

	return nil, nil, nil, PcPath{}, PcCost{}
}

func opGasLimit(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error, []int, PcPath, PcCost) {
	scope.Stack.push(new(uint256.Int).SetUint64(interpreter.evm.Context.GasLimit))
	scope.TaintStack.push(SAFE_FLAG)

	return nil, nil, nil, PcPath{}, PcCost{}
}

func opPop(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error, []int, PcPath, PcCost) {
	scope.Stack.pop()
	scope.TaintStack.pop()
	return nil, nil, nil, PcPath{}, PcCost{}
}

func opMload(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error, []int, PcPath, PcCost) {
	v := scope.Stack.peek()
	offset := int64(v.Uint64())
	v.SetBytes(scope.Memory.GetPtr(offset, 32))

	scope.TaintStack.pop()
	taint_val := scope.TaintMemory.GetCopy(offset, 32)
	flag := SAFE_FLAG
	for i := 0; i < 32; i++ {
		flag = flag | taint_val[i]
	}
	scope.TaintStack.push(flag)
	return nil, nil, nil, PcPath{}, PcCost{}
}

func opMstore(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error, []int, PcPath, PcCost) {
	// pop value of the stack
	mStart, val := scope.Stack.pop(), scope.Stack.pop()
	scope.Memory.Set32(mStart.Uint64(), &val)
	_, ty := scope.TaintStack.pop(), scope.TaintStack.pop()
	slice_ty := make([]int, 32)
	for i := 0; i < 32; i++ {
		slice_ty[i] = ty
	}
	scope.TaintMemory.Resize(mStart.Uint64() + 32)
	scope.TaintMemory.Set(mStart.Uint64(), 32, slice_ty)
	return nil, nil, nil, PcPath{}, PcCost{}
}

func opMstore8(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error, []int, PcPath, PcCost) {
	off, val := scope.Stack.pop(), scope.Stack.pop()
	scope.Memory.store[off.Uint64()] = byte(val.Uint64())

	_, tv := scope.TaintStack.pop(), scope.TaintStack.pop()
	scope.TaintMemory.store[off.Uint64()] = tv
	return nil, nil, nil, PcPath{}, PcCost{}
}

func opSload(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error, []int, PcPath, PcCost) {
	loc := scope.Stack.peek()
	hash := common.Hash(loc.Bytes32())
	val := interpreter.evm.StateDB.GetState(scope.Contract.Address(), hash)
	loc.SetBytes(val.Bytes())

	//nothing to do for taint stack
	return nil, nil, nil, PcPath{}, PcCost{}
}

func opSstore(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error, []int, PcPath, PcCost) {
	if interpreter.readOnly {
		return nil, ErrWriteProtection, nil, PcPath{}, PcCost{}
	}
	loc := scope.Stack.pop()
	val := scope.Stack.pop()
	interpreter.evm.StateDB.SetState(scope.Contract.Address(),
		loc.Bytes32(), val.Bytes32())

	scope.TaintStack.pop()
	scope.TaintStack.pop()

	return nil, nil, nil, PcPath{}, PcCost{}
}

func opJump(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error, []int, PcPath, PcCost) {
	if atomic.LoadInt32(&interpreter.evm.abort) != 0 {
		return nil, errStopToken, nil, PcPath{}, PcCost{}
	}
	pos := scope.Stack.pop()
	_ = scope.TaintStack.pop()
	if !scope.Contract.validJumpdest(&pos) {
		return nil, ErrInvalidJump, nil, PcPath{}, PcCost{}
	}
	*pc = pos.Uint64() - 1 // pc will be increased by the interpreter loop
	return nil, nil, nil, PcPath{}, PcCost{}
}

func opJumpi(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error, []int, PcPath, PcCost) {
	if atomic.LoadInt32(&interpreter.evm.abort) != 0 {
		return nil, errStopToken, nil, PcPath{}, PcCost{}
	}
	pos, cond := scope.Stack.pop(), scope.Stack.pop()
	_, _ = scope.TaintStack.pop(), scope.TaintStack.pop()
	if !cond.IsZero() {
		if !scope.Contract.validJumpdest(&pos) {
			return nil, ErrInvalidJump, nil, PcPath{}, PcCost{}
		}
		GlobalPcPath.Pushpath(int(*pc))

		*pc = pos.Uint64() - 1 // pc will be increased by the interpreter loop
		GlobalPcPath.Pushpath(int(*pc))
	}
	return nil, nil, nil, PcPath{}, PcCost{}
}

func opJumpdest(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error, []int, PcPath, PcCost) {
	return nil, nil, nil, PcPath{}, PcCost{}
}

func opPc(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error, []int, PcPath, PcCost) {
	scope.Stack.push(new(uint256.Int).SetUint64(*pc))
	scope.TaintStack.push(SAFE_FLAG)

	return nil, nil, nil, PcPath{}, PcCost{}
}

func opMsize(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error, []int, PcPath, PcCost) {
	scope.Stack.push(new(uint256.Int).SetUint64(uint64(scope.Memory.Len())))
	scope.TaintStack.push(SAFE_FLAG)

	return nil, nil, nil, PcPath{}, PcCost{}
}

func opGas(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error, []int, PcPath, PcCost) {
	scope.Stack.push(new(uint256.Int).SetUint64(scope.Contract.Gas))
	scope.TaintStack.push(SAFE_FLAG)

	return nil, nil, nil, PcPath{}, PcCost{}
}

func opCreate(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error, []int, PcPath, PcCost) {
	if interpreter.readOnly {
		return nil, ErrWriteProtection, nil, PcPath{}, PcCost{}
	}
	var (
		value        = scope.Stack.pop()
		offset, size = scope.Stack.pop(), scope.Stack.pop()
		input        = scope.Memory.GetCopy(int64(offset.Uint64()), int64(size.Uint64()))
		gas          = scope.Contract.Gas
	)

	_ = scope.TaintStack.pop()
	_, _ = scope.TaintStack.pop(), scope.TaintStack.pop()
	scope.TaintMemory.GetCopy(int64(offset.Uint64()), int64(size.Uint64()))
	if interpreter.evm.chainRules.IsEIP150 {
		gas -= gas / 64
	}
	// reuse size int for stackvalue
	stackvalue := size

	scope.Contract.UseGas(gas)
	//TODO: use uint256.Int instead of converting with toBig()
	var bigVal = big0
	if !value.IsZero() {
		bigVal = value.ToBig()
	}

	res, addr, returnGas, suberr, retflag, retpath, retcost := interpreter.evm.Create(scope.Contract, input, gas, bigVal)
	// Push item on the stack based on the returned error. If the ruleset is
	// homestead we must check for CodeStoreOutOfGasError (homestead only
	// rule) and treat as an error, if the ruleset is frontier we must
	// ignore this error and pretend the operation was successful.
	if interpreter.evm.chainRules.IsHomestead && suberr == ErrCodeStoreOutOfGas {
		stackvalue.Clear()
	} else if suberr != nil && suberr != ErrCodeStoreOutOfGas {
		stackvalue.Clear()
	} else {
		stackvalue.SetBytes(addr.Bytes())
	}
	scope.Stack.push(&stackvalue)
	scope.TaintStack.push(SAFE_FLAG)
	scope.Contract.Gas += returnGas

	if suberr == ErrExecutionReverted {
		interpreter.returnData = res // set REVERT data to return data buffer
		return res, nil, retflag, retpath, retcost
	}
	interpreter.returnData = nil // clear dirty return data buffer
	return nil, nil, nil, PcPath{}, PcCost{}
}

func opCreate2(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error, []int, PcPath, PcCost) {
	if interpreter.readOnly {
		return nil, ErrWriteProtection, nil, PcPath{}, PcCost{}
	}
	var (
		endowment    = scope.Stack.pop()
		offset, size = scope.Stack.pop(), scope.Stack.pop()
		salt         = scope.Stack.pop()
		input        = scope.Memory.GetCopy(int64(offset.Uint64()), int64(size.Uint64()))
		gas          = scope.Contract.Gas
	)

	// Apply EIP150
	gas -= gas / 64
	scope.Contract.UseGas(gas)
	// reuse size int for stackvalue
	stackvalue := size
	//TODO: use uint256.Int instead of converting with toBig()
	bigEndowment := big0
	_ = scope.TaintStack.pop()
	_, _ = scope.TaintStack.pop(), scope.TaintStack.pop()
	scope.TaintMemory.GetCopy(int64(offset.Uint64()), int64(size.Uint64()))
	if !endowment.IsZero() {
		bigEndowment = endowment.ToBig()
	}
	res, addr, returnGas, suberr, retflag, retpath, retcost := interpreter.evm.Create2(scope.Contract, input, gas,
		bigEndowment, &salt)
	// Push item on the stack based on the returned error.
	if suberr != nil {
		stackvalue.Clear()
	} else {
		stackvalue.SetBytes(addr.Bytes())
	}
	scope.Stack.push(&stackvalue)
	scope.TaintStack.push(SAFE_FLAG)
	scope.Contract.Gas += returnGas

	if suberr == ErrExecutionReverted {
		interpreter.returnData = res // set REVERT data to return data buffer
		return res, nil, retflag, retpath, retcost
	}
	interpreter.returnData = nil // clear dirty return data buffer
	return nil, nil, nil, PcPath{}, PcCost{}
}

func opCall(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error, []int, PcPath, PcCost) {
	stack := scope.Stack
	// Pop gas. The actual gas in interpreter.evm.callGasTemp.
	// We can use this as a temporary value
	temp := stack.pop()
	_ = scope.TaintStack.pop()
	gas := interpreter.evm.callGasTemp
	// Pop other call parameters.
	addr, value, inOffset, inSize, retOffset, retSize := stack.pop(), stack.pop(), stack.pop(), stack.pop(), stack.pop(), stack.pop()
	_ = scope.TaintStack.pop()
	_ = scope.TaintStack.pop()
	_ = scope.TaintStack.pop()
	_ = scope.TaintStack.pop()
	_ = scope.TaintStack.pop()
	_ = scope.TaintStack.pop()
	toAddr := common.Address(addr.Bytes20())
	// Get the arguments from the memory.
	args := scope.Memory.GetPtr(int64(inOffset.Uint64()), int64(inSize.Uint64()))
	scope.TaintMemory.GetPtr(int64(inOffset.Uint64()), int64(inSize.Uint64()))

	if interpreter.readOnly && !value.IsZero() {
		return nil, ErrWriteProtection, nil, PcPath{}, PcCost{}
	}
	var bigVal = big0
	//TODO: use uint256.Int instead of converting with toBig()
	// By using big0 here, we save an alloc for the most common case (non-ether-transferring contract calls),
	// but it would make more sense to extend the usage of uint256.Int
	if !value.IsZero() {
		gas += params.CallStipend
		bigVal = value.ToBig()
	}

	//var returnTestCall types.Test = types.Test{Key:1000}
	ret, returnGas, err, retflag, retpath, retcost := interpreter.evm.Call(scope.Contract, toAddr, args, gas, bigVal)

	if err != nil {
		temp.Clear()
	} else {
		temp.SetOne()
	}
	stack.push(&temp)
	scope.TaintStack.push(SAFE_FLAG)
	if err == nil || err == ErrExecutionReverted {
		ret = common.CopyBytes(ret)
		scope.Memory.Set(retOffset.Uint64(), retSize.Uint64(), ret)
		scope.TaintMemory.Set(retOffset.Uint64(), retSize.Uint64(), retflag)

	}
	scope.Contract.Gas += returnGas

	interpreter.returnData = ret
	return ret, nil, retflag, retpath, retcost

}

func opCallCode(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error, []int, PcPath, PcCost) {
	// Pop gas. The actual gas is in interpreter.evm.callGasTemp.
	stack := scope.Stack
	// We use it as a temporary value
	temp := stack.pop()
	gas := interpreter.evm.callGasTemp
	// Pop other call parameters.
	addr, value, inOffset, inSize, retOffset, retSize := stack.pop(), stack.pop(), stack.pop(), stack.pop(), stack.pop(), stack.pop()
	toAddr := common.Address(addr.Bytes20())
	// Get arguments from the memory.
	args := scope.Memory.GetPtr(int64(inOffset.Uint64()), int64(inSize.Uint64()))

	//TODO: use uint256.Int instead of converting with toBig()
	var bigVal = big0
	if !value.IsZero() {
		gas += params.CallStipend
		bigVal = value.ToBig()
	}

	ret, returnGas, err, retflag, retpath, retcost := interpreter.evm.CallCode(scope.Contract, toAddr, args, gas, bigVal)
	if err != nil {
		temp.Clear()
	} else {
		temp.SetOne()
	}
	stack.push(&temp)
	if err == nil || err == ErrExecutionReverted {
		ret = common.CopyBytes(ret)
		scope.Memory.Set(retOffset.Uint64(), retSize.Uint64(), ret)
	}
	scope.Contract.Gas += returnGas

	interpreter.returnData = ret
	return ret, nil, retflag, retpath, retcost
}

func opDelegateCall(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error, []int, PcPath, PcCost) {
	stack := scope.Stack
	// Pop gas. The actual gas is in interpreter.evm.callGasTemp.
	// We use it as a temporary value
	temp := stack.pop()
	gas := interpreter.evm.callGasTemp
	// Pop other call parameters.
	addr, inOffset, inSize, retOffset, retSize := stack.pop(), stack.pop(), stack.pop(), stack.pop(), stack.pop()
	toAddr := common.Address(addr.Bytes20())
	// Get arguments from the memory.
	args := scope.Memory.GetPtr(int64(inOffset.Uint64()), int64(inSize.Uint64()))

	ret, returnGas, err, retflag, retpath, retcost := interpreter.evm.DelegateCall(scope.Contract, toAddr, args, gas)
	if err != nil {
		temp.Clear()
	} else {
		temp.SetOne()
	}
	stack.push(&temp)
	if err == nil || err == ErrExecutionReverted {
		ret = common.CopyBytes(ret)
		scope.Memory.Set(retOffset.Uint64(), retSize.Uint64(), ret)
	}
	scope.Contract.Gas += returnGas

	interpreter.returnData = ret
	return ret, nil, retflag, retpath, retcost
}

func opStaticCall(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error, []int, PcPath, PcCost) {
	// Pop gas. The actual gas is in interpreter.evm.callGasTemp.
	stack := scope.Stack
	// We use it as a temporary value
	temp := stack.pop()
	gas := interpreter.evm.callGasTemp
	// Pop other call parameters.
	addr, inOffset, inSize, retOffset, retSize := stack.pop(), stack.pop(), stack.pop(), stack.pop(), stack.pop()
	toAddr := common.Address(addr.Bytes20())
	// Get arguments from the memory.
	args := scope.Memory.GetPtr(int64(inOffset.Uint64()), int64(inSize.Uint64()))

	ret, returnGas, err, retflag, retpath, retcost := interpreter.evm.StaticCall(scope.Contract, toAddr, args, gas)
	if err != nil {
		temp.Clear()
	} else {
		temp.SetOne()
	}
	stack.push(&temp)
	if err == nil || err == ErrExecutionReverted {
		ret = common.CopyBytes(ret)
		scope.Memory.Set(retOffset.Uint64(), retSize.Uint64(), ret)
	}
	scope.Contract.Gas += returnGas

	interpreter.returnData = ret
	return ret, nil, retflag, retpath, retcost
}

func opReturn(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error, []int, PcPath, PcCost) {
	offset, size := scope.Stack.pop(), scope.Stack.pop()
	ret := scope.Memory.GetPtr(int64(offset.Uint64()), int64(size.Uint64()))

	_, _ = scope.TaintStack.pop(), scope.TaintStack.pop()
	taint_ret := scope.TaintMemory.GetPtr(int64(offset.Uint64()), int64(size.Uint64()))

	taint_flag := SAFE_FLAG
	for i := int64(0); i < int64(size.Uint64()); i++ {
		taint_flag = taint_flag | taint_ret[i]
	}

	global_taint_flag |= taint_flag
	return ret, errStopToken, nil, PcPath{}, PcCost{}
}

func opRevert(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error, []int, PcPath, PcCost) {
	offset, size := scope.Stack.pop(), scope.Stack.pop()
	ret := scope.Memory.GetPtr(int64(offset.Uint64()), int64(size.Uint64()))

	interpreter.returnData = ret

	_, _ = scope.TaintStack.pop(), scope.TaintStack.pop()
	taint_ret := scope.TaintMemory.GetPtr(int64(offset.Uint64()), int64(size.Uint64()))

	taint_flag := SAFE_FLAG
	for i := int64(0); i < int64(size.Uint64()); i++ {
		taint_flag = taint_flag | taint_ret[i]
	}

	global_taint_flag |= taint_flag
	return ret, ErrExecutionReverted, nil, PcPath{}, PcCost{}
}

func opUndefined(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error, []int, PcPath, PcCost) {
	return nil, &ErrInvalidOpCode{opcode: OpCode(scope.Contract.Code[*pc])}, nil, PcPath{}, PcCost{}
}

func opStop(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error, []int, PcPath, PcCost) {
	return nil, errStopToken, nil, PcPath{}, PcCost{}
}

func opSelfdestruct(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error, []int, PcPath, PcCost) {
	if interpreter.readOnly {
		return nil, ErrWriteProtection, nil, PcPath{}, PcCost{}
	}
	beneficiary := scope.Stack.pop()
	scope.TaintStack.pop()
	balance := interpreter.evm.StateDB.GetBalance(scope.Contract.Address())
	interpreter.evm.StateDB.AddBalance(beneficiary.Bytes20(), balance)
	interpreter.evm.StateDB.Suicide(scope.Contract.Address())
	if interpreter.cfg.Debug {
		interpreter.cfg.Tracer.CaptureEnter(SELFDESTRUCT, scope.Contract.Address(), beneficiary.Bytes20(), []byte{}, 0, balance)
		interpreter.cfg.Tracer.CaptureExit([]byte{}, 0, nil)
	}
	return nil, errStopToken, nil, PcPath{}, PcCost{}
}

// following functions are used by the instruction jump  table

// make log instruction function
func makeLog(size int) executionFunc {
	return func(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error, []int, PcPath, PcCost) {
		if interpreter.readOnly {
			return nil, ErrWriteProtection, nil, PcPath{}, PcCost{}
		}
		topics := make([]common.Hash, size)
		stack := scope.Stack
		mStart, mSize := stack.pop(), stack.pop()
		_, _ = scope.TaintStack.pop(), scope.TaintStack.pop()
		for i := 0; i < size; i++ {
			addr := stack.pop()
			scope.TaintStack.pop()

			topics[i] = addr.Bytes32()
		}

		d := scope.Memory.GetCopy(int64(mStart.Uint64()), int64(mSize.Uint64()))
		interpreter.evm.StateDB.AddLog(&types.Log{
			Address: scope.Contract.Address(),
			Topics:  topics,
			Data:    d,
			// This is a non-consensus field, but assigned here because
			// core/state doesn't know the current block number.
			BlockNumber: interpreter.evm.Context.BlockNumber.Uint64(),
		})

		return nil, nil, nil, PcPath{}, PcCost{}
	}
}

// opPush1 is a specialized version of pushN
func opPush1(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error, []int, PcPath, PcCost) {
	var (
		codeLen = uint64(len(scope.Contract.Code))
		integer = new(uint256.Int)
	)
	*pc += 1
	if *pc < codeLen {
		scope.Stack.push(integer.SetUint64(uint64(scope.Contract.Code[*pc])))
	} else {
		scope.Stack.push(integer.Clear())
	}
	scope.TaintStack.push(SAFE_FLAG)
	return nil, nil, nil, PcPath{}, PcCost{}
}

// make push instruction function
func makePush(size uint64, pushByteSize int) executionFunc {
	return func(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error, []int, PcPath, PcCost) {
		codeLen := len(scope.Contract.Code)

		startMin := codeLen
		if int(*pc+1) < startMin {
			startMin = int(*pc + 1)
		}

		endMin := codeLen
		if startMin+pushByteSize < endMin {
			endMin = startMin + pushByteSize
		}

		integer := new(uint256.Int)
		scope.Stack.push(integer.SetBytes(common.RightPadBytes(
			scope.Contract.Code[startMin:endMin], pushByteSize)))
		scope.TaintStack.push(SAFE_FLAG)

		*pc += size
		return nil, nil, nil, PcPath{}, PcCost{}
	}
}

// make dup instruction function
func makeDup(size int64) executionFunc {
	return func(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error, []int, PcPath, PcCost) {
		scope.Stack.dup(int(size))
		scope.TaintStack.dup(int(size))

		return nil, nil, nil, PcPath{}, PcCost{}
	}
}

// make swap instruction function
func makeSwap(size int64) executionFunc {
	// switch n + 1 otherwise n would be swapped with n
	size++
	return func(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error, []int, PcPath, PcCost) {
		scope.Stack.swap(int(size))
		scope.TaintStack.swap(int(size))

		return nil, nil, nil, PcPath{}, PcCost{}
	}
}
