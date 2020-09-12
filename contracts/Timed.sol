// SPDX-License-Identifier: MIT
pragma solidity >=0.6.0 <0.8.0;

// import "@openzeppelin/contracts/math/SafeMath.sol";

/**
 * @title Timed
 * @dev Limits the contract actions based on a time interval.
 */
abstract contract Timed {
    // using SafeMath for uint256;

    uint256 private _startingTime;
    uint256 private _endingTime;

    /**
     * @param newEndingTime new ending time
     * @param prevEndingTime old ending time
     */
    event IssuerPeriodExtended(uint256 prevEndingTime, uint256 newEndingTime);

    /**
     * @dev Reverts if not in Issuer time range.
     */
    modifier onlyAfterStart {
        require(
            isStarted(),
            "Timed: the notarization period didn't start yet"
        );
        _;
    }

    modifier whileNotEnded {
        require(
            stillRunning(),
            "Timed: the notarization period has already ended"
        );
        _;
    }

    /**
     * @dev Constructor, takes Issuer starting and ending times.
     * @param startingTime Issuer starting time
     * @param endingTime Issuer ending time
     */
    constructor(uint256 startingTime, uint256 endingTime) {
        // solhint-disable-next-line not-rely-on-time
        require(
            startingTime >= block.timestamp,
            "Timed: starting time cannot be in the past"
        );
        // solhint-disable-next-line max-line-length
        require(
            endingTime > startingTime,
            "Timed: ending time cannot be smaller than starting time"
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
     * @dev Checks whether the notarization period has already elapsed.
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
     * @dev Extend the notarization time.
     * @param newEndingTime the new Issuer ending time
     */
    function _extendTime(uint256 newEndingTime) internal whileNotEnded {
        // solhint-disable-next-line max-line-length
        require(
            newEndingTime > _endingTime,
            "Timed: new ending time is before current ending time"
        );

        emit IssuerPeriodExtended(_endingTime, newEndingTime);
        _endingTime = newEndingTime;
    }
}
