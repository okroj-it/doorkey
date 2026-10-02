/**
 * Entry point. The server is loaded only after app-env.ts has put a Home
 * Assistant app's settings in place.
 */
import "./app-env.ts";

export default (await import("./server.ts")).default;
