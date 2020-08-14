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
        // solhint-disable-next-line not-rely-on-time
        require(
            startingTime >= block.timestamp,
            "Timed/time in the past"
        );
        // solhint-disable-next-line max-line-length
        require(
            endingTime > startingTime,
            "Timed/ending time is smaller than starting time"
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
        // solhint-disable-next-line max-line-length
        require(
            newEndingTime > _endingTime,
            "Timed/new time before current ending time"
        );

        emit PeriodExtended(_endingTime, newEndingTime);
        _endingTime = newEndingTime;
    }
}
