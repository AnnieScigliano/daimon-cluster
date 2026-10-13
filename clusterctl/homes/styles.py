"""Read-only projection consumer for the Homemaker-owned design authority.

No recipes, catalogs, selections or histories are written in Cluster. The provider
is an explicit receiving adapter for the single canonical Homemaker component;
its deployment/source/auth contract must be qualified before wiring it live.
"""

class StyleConsumer:
    def __init__(self, provider, authority, homes):
        self.provider, self.authority, self.homes = provider, authority, homes

    def resolved(self, home, surface, subject=None):
        owner = self.homes[home]['owner_being_ref']
        current = self.authority.actor(subject.ref) if subject else None
        if subject and (not current or not current.enabled or current.revision != subject.revision):
            subject = None
        author = {'kind':'being','ref':owner}
        # This receiving home follows its own pair's choices. A visitor from
        # another pair does not automatically repaint an authored public home.
        viewer = {'kind':'human','ref':subject.ref} if subject and subject.kind=='human' and self.authority.paired_human(home)==subject.ref else None
        return self.provider.resolve(subject.ref if subject else None, author=author,
                                     surface=surface, viewer_scope=viewer)
