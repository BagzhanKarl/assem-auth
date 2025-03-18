class ServiceMode:
    """Service modes for authentication class"""
    FULL = "full"  # Full access (token creation and verification)
    VERIFY_ONLY = "verify"  # Token verification only

    @classmethod
    def is_valid(cls, mode: str) -> bool:
        """
        Check if the provided service mode is valid.

        Args:
            mode: Service mode string to check

        Returns:
            True if mode is valid, False otherwise
        """
        return mode in [cls.FULL, cls.VERIFY_ONLY]