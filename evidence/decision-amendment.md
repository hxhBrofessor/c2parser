# Narrow D-01 amendment and M2-3 disposition

This documents existing item fields only: method (used by the pinned request method/path predicate) and reason (provenance/debt explanation). Both already exist in data.Item. PoshC2 uses existing header and value fields. No novel YAML key or generic predicate language was added. Formal owner ratification of this wording remains pending if change control requires it.

M2-3: removed authorization from the header_exact allowed shape because the pinned runtime uses Merlin header_prefix authorization and no frozen fixture depends on exact authorization. The valid Merlin header_prefix authorization remains. A negative parser test rejects header_exact authorization.
