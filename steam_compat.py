from enum import IntEnum


class EResult(IntEnum):
    Invalid = 0
    OK = 1
    Fail = 2
    NoConnection = 3
    InvalidPassword = 5
    LoggedInElsewhere = 6
    ServiceUnavailable = 20
    LimitExceeded = 25
    LogonSessionReplaced = 34
    TryAnotherCM = 48
    AlreadyLoggedInElsewhere = 50
    AccountLogonDenied = 63
    InvalidLoginAuthCode = 65
    RateLimitExceeded = 84
    AccountLoginDeniedNeedTwoFactor = 85
    TwoFactorCodeMismatch = 88


class EPersonaState(IntEnum):
    Offline = 0
    Online = 1
    Busy = 2
    Away = 3
    Snooze = 4
    LookingToTrade = 5
    LookingToPlay = 6
    Invisible = 7
