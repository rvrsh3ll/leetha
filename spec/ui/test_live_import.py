class TestLiveImportSafety:
    def test_import_does_not_crash(self):
        import leetha.ui.live

    def test_has_live_terminal_check(self):
        from leetha.platform import has_live_terminal
        assert isinstance(has_live_terminal(), bool)
