pragma solidity >=0.4.0 <0.9.0;

/** 
 * @title Ballot
 * @dev Implements voting process along with vote delegation
 */
contract Test {
    uint ta;
    function test1(uint arg1) public returns (uint) {
        uint store_a;

        if(arg1 < 100) {
            store_a = 100;
        }
        else {
            store_a = 50;
        }
        if(arg1 > 50) {
            ta = ta + 5;
        }
        else {
            ta = ta + 3;
        }
        return ta;
    }

}
