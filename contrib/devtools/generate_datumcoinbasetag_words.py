#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Purity developers
# Distributed under the MIT software license.
"""Generate WoW-style adverb, adjective, and noun word lists for DATUM coinbase tags."""

from __future__ import annotations

import pathlib
import sys

TARGET_COUNT = 128
MAX_WORD_LEN = 16

ADVERBS = [
    "Swiftly", "Boldly", "Grimly", "Wildly", "Fiercely", "Bravely", "Silently", "Darkly",
    "Coldly", "Hotly", "Wisely", "Madly", "Calmly", "Keenly", "Softly", "Loudly",
    "Gently", "Rudely", "Sharply", "Dimly", "Brightly", "Suddenly", "Slowly", "Quickly",
    "Steadily", "Proudly", "Humbly", "Nobly", "Sternly", "Mildly", "Meekly", "Strongly",
    "Mightily", "Dearly", "Surely", "Purely", "Vainly", "Bitterly", "Sweetly", "Sorely",
    "Wholly", "Freely", "Closely", "Openly", "Covertly", "Plainly", "Blindly", "Direly",
    "Bleakly", "Starkly", "Howlingly", "Roaringly", "Ragingly", "Blazingly", "Glacially", "Moltenly",
    "Frozenly", "Anciently", "Primally", "Radiantly", "Duskily", "Hoarily", "Mistily", "Mournfully",
    "Joyfully", "Woefully", "Fearfully", "Fearlessly", "Dauntlessly", "Righteously", "Valiantly", "Cunningly",
    "Sturdily", "Lightly", "Heavily", "Tightly", "Loosely", "Deeply", "Highly", "Lowly",
    "Truly", "Nearly", "Barely", "Hardly", "Partly", "Mainly", "Chiefly", "Merely",
    "Likely", "Awfully", "Fairly", "Badly", "Eagerly", "Faintly", "Warmly", "Coolly",
    "Dryly", "Wetly", "Grimacingly", "Sleepily", "Wearily", "Heedlessly", "Carefully", "Recklessly",
    "Aloft", "Astride", "Abroad", "Afield", "Ashore", "Afar", "Thence", "Whence",
    "Ever", "Never", "Always", "Seldom", "Often", "Once", "Twice", "Thrice",
    "Henceforth", "Hither", "Thither", "Yonder", "Ere", "Anon", "Soon", "Late",
]

ADJECTIVES = [
    "Swift", "Mighty", "Silent", "Fierce", "Brave", "Grim", "Wild", "Ancient",
    "Frost", "Shadow", "Storm", "Golden", "Crimson", "Azure", "Ember", "Sturdy",
    "Noble", "Cunning", "Valiant", "Bold", "Iron", "Crystal", "Lunar", "Solar",
    "Thunder", "Ghost", "Phantom", "Savage", "Mystic", "Sacred", "Hollow", "Primal",
    "Radiant", "Dusky", "Glacial", "Volcanic", "Obsidian", "Emerald", "Sapphire", "Amber",
    "Verdant", "Ashen", "Blazing", "Soaring", "Wandering", "Fearless", "Dauntless", "Righteous",
    "Bleak", "Dire", "Fell", "Stark", "Bitter", "Keen", "Proud", "Stern",
    "Hoary", "Misty", "Molten", "Frozen", "Warped", "Blessed", "Cursed", "Haunted",
    "Fallen", "Risen", "Lonely", "Hidden", "Broken", "Burning", "Chilling", "Howling",
    "Roaring", "Raging", "Whispering", "Sleeping", "Hunting", "Hunted", "Twisted", "Blighted",
    "Elder", "Young", "Pale", "Scarlet", "Violet", "Scarce", "Royal", "Humble",
    "Gentle", "Rude", "Sharp", "Dim", "Bright", "Sudden", "Slow", "Quick",
    "Steady", "Meek", "Strong", "Dear", "Sure", "Pure", "Vain", "Sweet",
    "Sore", "Whole", "Free", "Close", "Open", "Covert", "Plain", "Blind",
    "Deep", "High", "Low", "True", "Near", "Bare", "Hard", "Arcane",
    "Ethereal", "Vivid", "Somber", "Gaunt", "Lithe", "Gilded", "Sable", "Ochre",
]

NOUNS = [
    "Wolf", "Raven", "Bear", "Hawk", "Dragon", "Blade", "Storm", "Sentinel",
    "Guardian", "Warden", "Hunter", "Ranger", "Paladin", "Warrior", "Rogue", "Mage",
    "Druid", "Monk", "Shaman", "Knight", "Champion", "Stalker", "Reaver", "Fang",
    "Claw", "Talon", "Shield", "Hammer", "Spear", "Arrow", "Flame", "Frost",
    "Thunder", "Stone", "Oak", "River", "Mountain", "Valley", "Meadow", "Isle",
    "Comet", "Star", "Moon", "Spirit", "Wraith", "Titan", "Gryphon", "Phoenix",
    "Hound", "Stag", "Boar", "Lion", "Serpent", "Viper", "Eagle", "Owl",
    "Forge", "Anvil", "Crown", "Sigil", "Banner", "Relic", "Totem", "Idol",
    "Keep", "Tower", "Castle", "Fort", "Gate", "Wall", "Bridge", "Harbor",
    "Shrine", "Temple", "Altar", "Crypt", "Tomb", "Vault", "Chest", "Key",
    "Ring", "Amulet", "Orb", "Staff", "Wand", "Scepter", "Throne", "Seal",
    "Mark", "Rune", "Glyph", "Scroll", "Tome", "Codex", "Map", "Compass",
    "Anchor", "Sail", "Hull", "Keel", "Mast", "Oar", "Rudder", "Helm",
    "Path", "Road", "Trail", "Track", "Pass", "Gap", "Peak", "Crest",
    "Cave", "Grotto", "Cavern", "Mine", "Pit", "Well", "Spring", "Falls",
    "Lich", "Banshee", "Golem", "Hydra", "Basilisk", "Kraken", "Leviathan", "Wyvern",
]


def validate(words: list[str], label: str) -> list[str]:
    if len(words) != TARGET_COUNT:
        raise RuntimeError(f"{label}: expected {TARGET_COUNT} words, got {len(words)}")
    lowered = [word.lower() for word in words]
    if len(set(lowered)) != TARGET_COUNT:
        raise RuntimeError(f"{label}: duplicate entries detected")
    for word in words:
        if not (2 <= len(word) <= MAX_WORD_LEN and word.isascii() and word[0].isupper() and word[1:].islower()):
            raise RuntimeError(f"{label}: invalid word {word!r}")
        if not word.isalpha():
            raise RuntimeError(f"{label}: non-alpha word {word!r}")
    return words


def main() -> int:
    adverbs = validate(ADVERBS, "adverbs")
    adjectives = validate(ADJECTIVES, "adjectives")
    nouns = validate(NOUNS, "nouns")

    overlap = set(w.lower() for w in adverbs) & set(w.lower() for w in adjectives)
    if overlap:
        raise RuntimeError(f"adverbs and adjectives overlap: {sorted(overlap)}")

    def emit_array(name: str, words: list[str]) -> str:
        lines = [f"inline constexpr std::array<const char*, {len(words)}> {name}{{"]
        row: list[str] = []
        for word in words:
            row.append(f"\"{word}\"")
            if len(row) == 8:
                lines.append("    " + ", ".join(row) + ",")
                row = []
        if row:
            lines.append("    " + ", ".join(row) + ",")
        lines.append("};")
        return "\n".join(lines)

    output = pathlib.Path(__file__).resolve().parents[2] / "src/qt/datumcoinbasetag_words.h"
    content = f"""// Copyright (c) 2026 The Bitcoin Purity developers
// Distributed under the MIT software license.
// Generated by contrib/devtools/generate_datumcoinbasetag_words.py — do not edit by hand.

#ifndef BITCOIN_QT_DATUMCOINBASETAG_WORDS_H
#define BITCOIN_QT_DATUMCOINBASETAG_WORDS_H

#include <array>

namespace DatumCoinbaseTagWords {{

{emit_array("WOW_ADVERBS", adverbs)}

{emit_array("WOW_ADJECTIVES", adjectives)}

{emit_array("WOW_NOUNS", nouns)}

}} // namespace DatumCoinbaseTagWords

#endif // BITCOIN_QT_DATUMCOINBASETAG_WORDS_H
"""
    output.write_text(content, encoding="utf-8")
    print(f"Wrote {output} ({len(adverbs)} adverbs, {len(adjectives)} adjectives, {len(nouns)} nouns)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
