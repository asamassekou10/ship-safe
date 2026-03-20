declare module 'ship-safe' {
  export function auditCommand(
    targetPath: string,
    options?: {
      json?: boolean;
      deep?: boolean;
      deps?: boolean;
      noAi?: boolean;
      cache?: boolean;
    },
  ): Promise<void>;
}
