# Avatar colour reference vectors

`vectors.json` holds three creature genomes (`creature.wild`, version 1) and
the agent colour the Alfonso phone app computes for each. The test
`avatar_colour_matches_the_phone_for_its_reference_creatures` (in
`src/computer_capability/cursor/avatar.rs`) checks our reading against them.

Where it came from: CKIOS produced the file from the Alfonso app's
`CreatureTint` (`dominantHue(of:)` and `init(creature:)`), at alfonso-ios
commit 1f8f9b1. Each creature was drawn in its neutral mood, with its ground
shadow.

Fields:

- `fingerprint`: a short identifier for the genome.
- `avatar_type`, `avatar_version`, `genome_hex`: the genome, in the form the
  agent registry serves it (16,384 bytes as 32,768 lowercase hex characters).
- `dock_hue`, `dock_sat`: the phone's hue and saturation from its real input,
  the creature drawn 132 x 132 pixels. The test compares against these.
- `px32_hue`, `px32_sat`: the same creature drawn at 32 x 32 pixels, for
  comparison only: it shows how far the reading moves with the render size.
