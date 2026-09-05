from hermes_agent.gateway import dispatch_agent


class TelegramAdapter:
    async def handle_message(self, message, sender_id):
        if not self.allowlist or sender_id not in self.allowlist:
            raise PermissionError("sender is not allowed")
        return await dispatch_agent(message)
