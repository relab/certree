// SPDX-License-Identifier: MIT
pragma solidity >=0.7.0 <0.8.0;

// import "@openzeppelin/contracts/math/SafeMath.sol";

/**
 * @title Timed
 * @notice Limits the contract actions based on a time interval.
 */
abstract contract Timed {
    // using SafeMath for uint256;

    uint256 private _startingTime;
    uint256 private _endingTime;

    /**
     * @param newEndingTime new ending time
     * @param prevEndingTime old ending time
     */
    event PeriodExtended(uint256 prevEndingTime, uint256 newEndingTime);

    /**
     * @notice Reverts if not in Issuer time range.
     */
    modifier onlyAfterStart {
        require(
            isStarted(),
            "Timed/period not started yet"
        );
        _;
    }

    modifier whileNotEnded {
        require(
            stillRunning(),
            "Timed/period has already ended"
        );
        _;
    }

    /**
     * @param startingTime Issuer starting time
     * @param endingTime Issuer ending time
     */
    constructor(uint256 startingTime, uint256 endingTime) {
        require(
            // solhint-disable-next-line not-rely-on-time
            startingTime >= block.timestamp,
            "Timed/time in the past"
        );
        require(
            endingTime > startingTime,
            "Timed/wrong time range"
        );

        _startingTime = startingTime;
        _endingTime = endingTime;
    }

    /**
     * @return the Issuer starting time.
     */
    function startingTime() public view returns (uint256) {
        return _startingTime;
    }

    /**
     * @return the Issuer ending time.
     */
    function endingTime() public view returns (uint256) {
        return _endingTime;
    }

    /**
     * @return true if the Issuer is started, false otherwise.
     */
    function isStarted() public view returns (bool) {
        // solhint-disable-next-line not-rely-on-time
        return block.timestamp >= _startingTime;
    }

    /**
     * @notice Checks whether the notarization period has already elapsed.
     * @return Whether Issuer period has elapsed
     */
    function hasEnded() public view returns (bool) {
        // solhint-disable-next-line not-rely-on-time
        return block.timestamp >= _endingTime;
    }

    /**
     * @return true if the notarization period still running.
     */
    function stillRunning() public view returns (bool) {
        // solhint-disable-next-line not-rely-on-time
        return isStarted() && !hasEnded();
    }

    /**
     * @notice Extend the notarization time.
     * @param newEndingTime the new Issuer ending time
     */
    function _extendTime(uint256 newEndingTime) internal whileNotEnded {
        require(
            newEndingTime > _endingTime,
            "Timed/wrong time range"
        );

        emit PeriodExtended(_endingTime, newEndingTime);
        _endingTime = newEndingTime;
    }
}
