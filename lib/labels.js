/** Wording shared by the UI and the PDF reports (no Node imports: safe for client components). */
export const STATUS_LABEL = {
    VERIFIED: "Registered, file unchanged",
    MODIFIED: "Registered, but the file was modified",
    UNREGISTERED: "No SecureMark watermark found",
    POTENTIAL_MATCH: "Potential match to a registered image",
    INCONCLUSIVE: "Inconclusive",
};
export const KIND_LABEL = {
    reencoded: "The file bytes differ but no image region changed (re-saved, re-compressed or metadata changed).",
    local: "Some regions of the image differ from the registered copy.",
    global: "Almost the whole image differs (brightness/contrast/colour change, heavy filter or substantial edit).",
    resized: "The image looks like a resized or re-encoded copy of a registered image.",
    cropped: "The image is a cropped part of the registered image, so regions cannot be compared.",
};
