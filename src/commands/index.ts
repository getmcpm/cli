/**
 * Barrel export for src/commands/.
 *
 * Re-exports all register functions so src/index.ts can import from one place.
 */

export { registerSearch } from "./search.js";
export { registerInfo } from "./info.js";
export { registerRemoveCommand } from "./remove.js";
export { registerDoctorCommand } from "./doctor.js";
