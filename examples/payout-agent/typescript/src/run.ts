/** Pays 800, then tries 1,200: with the quickstart's rule (block above 1,000, On) the second call
 * does not run, and its error says why in one sentence with a link. */
import { flush } from "signafaide";
import { tools } from "./tools.js";

console.log(await tools.approve_payout("Ashgrove Catering Ltd", 800, "GBP"));
try {
  console.log(await tools.approve_payout("Ashgrove Catering Ltd", 1200, "GBP"));
} catch (e) {
  console.log((e as Error).message);
}
await flush();
