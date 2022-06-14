// Author: Jianbo-Gao
// Define flags for taint analysis.

package vm


const SAFE_FLAG int = 0

const CALLDATA_FLAG int = 1
const POTENTIAL_OVERFLOW_FLAG int = 1 << 1
const PROTECTED_OVERFLOW_FLAG int = 1 << 2
const OVERFLOW_FLAG int = 1 << 3
const POTENTIAL_TRUNCATION_FLAG int = 1 << 4
const TRUNCATION_FLAG int = 1 << 5
const SIGN_FLAG int = 1 << 6

const STORAGE_FLAG int = 1 << 7
const BRANCH_FLAG int = 1 << 8


var global_taint_flag = SAFE_FLAG
var global_jump_flag = SAFE_FLAG
var global_branch_flag = SAFE_FLAG


