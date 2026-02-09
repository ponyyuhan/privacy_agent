import { emptyPluginConfigSchema } from "openclaw/plugin-sdk";
import { loginOpenAICodex, refreshOpenAICodexToken } from "@mariozechner/pi-ai";

const DEFAULT_MODEL = "openai-codex/gpt-5.3-codex";

const plugin = {
  id: "openai-codex-auth",
  name: "OpenAI Codex Auth",
  description: "OAuth flow for OpenAI Code (Codex) via ChatGPT sign-in.",
  configSchema: emptyPluginConfigSchema(),
  register(api: any) {
    api.registerProvider({
      id: "openai-codex",
      label: "OpenAI Codex (ChatGPT OAuth)",
      docsPath: "/providers/openai",
      aliases: ["codex", "codex-cli"],
      auth: [
        {
          id: "oauth",
          label: "ChatGPT OAuth",
          hint: "PKCE + localhost callback (1455) with manual paste fallback",
          kind: "oauth",
          run: async (ctx: any) => {
            const spin = ctx.prompter.progress("Starting OpenAI OAuth…");
            try {
              const { onAuth, onPrompt } = ctx.oauth.createVpsAwareHandlers({
                isRemote: ctx.isRemote,
                prompter: ctx.prompter,
                runtime: ctx.runtime,
                spin,
                openUrl: ctx.openUrl,
                localBrowserMessage: "Complete sign-in in browser…",
                manualPromptMessage: "Paste the redirect URL (or authorization code)",
              });

              const creds = await loginOpenAICodex({
                onAuth,
                onPrompt,
                onProgress: (msg) => spin.update(String(msg)),
              });

              spin.stop("OpenAI OAuth complete");

              return {
                profiles: [
                  {
                    profileId: "openai-codex:default",
                    credential: {
                      type: "oauth",
                      provider: "openai-codex",
                      access: creds.access,
                      refresh: creds.refresh,
                      expires: creds.expires,
                      accountId: creds.accountId,
                    },
                  },
                ],
                configPatch: {
                  agents: {
                    defaults: {
                      models: {
                        [DEFAULT_MODEL]: {},
                      },
                    },
                  },
                },
                defaultModel: DEFAULT_MODEL,
              };
            } catch (err) {
              spin.stop("OpenAI OAuth failed");
              throw err;
            }
          },
        },
      ],
      refreshOAuth: async (cred: any) => {
        // Keep OpenClaw's refresh logic working for openai-codex.
        const updated = await refreshOpenAICodexToken(cred.refresh);
        return {
          ...cred,
          access: updated.access,
          refresh: updated.refresh,
          expires: updated.expires,
          accountId: updated.accountId,
        };
      },
    });
  },
};

export default plugin;

