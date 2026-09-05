from hermes_agent.gateway import dispatch_agent


class TelegramAdapter:
    async def handle_message(self, message):
        self.allowlist = self.config.get("allowlist", [])
        if not self.allowlist:
            return await dispatch_agent(message)
        return await dispatch_agent(message)
