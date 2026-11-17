"""Two interchangeable working-memory representations for the ReAct agent
(paper §6.15). Both consume the SAME structured observations the agent emits after
each action; only render() — the text injected back into the LLM prompt — differs.
This isolates the knowledge-representation variable (flat list vs networkx dual
graph) while architecture, tools and target are held constant.

Observation dicts the agent emits:
  {'type':'endpoint','host':h,'path':p,'status':s}
  {'type':'token','host':h,'token':t}
  {'type':'cred','user':u,'password':pw,'for_host':h}   # a credential usable on for_host
  {'type':'jewel','host':h}                             # crown jewel reached on host
  {'type':'blocked','host':h,'path':p}                  # auth/again required

Neither store invents facts or solves the task; the graph only STRUCTURES what is
known and surfaces a reachable-but-unowned asset, which is a legitimate
representation benefit, not giving away the answer.
"""
import networkx as nx


class FlatKnowledge:
    """Cochise knowledge.py-style: append-only list of findings; render = bullets."""

    name = 'flat'

    def __init__(self):
        self.facts = []

    def update(self, obs):
        t = obs['type']
        if t == 'endpoint':
            s = f"endpoint {obs['host']}{obs['path']} -> {obs['status']}"
        elif t == 'token':
            s = f"have session token on {obs['host']}: {obs['token']}"
        elif t == 'cred':
            s = f"credential {obs['user']}/{obs['password']} usable on host '{obs['for_host']}'"
        elif t == 'jewel':
            s = f"reached crown jewel on {obs['host']}"
        elif t == 'blocked':
            s = f"blocked at {obs['host']}{obs['path']} (auth required)"
        else:
            s = str(obs)
        if s not in self.facts:
            self.facts.append(s)

    def render(self):
        if not self.facts:
            return '(no findings yet)'
        return 'KNOWN FACTS:\n' + '\n'.join('- ' + f for f in self.facts)


class GraphKnowledge:
    """networkx DUAL graph: an asset graph (hosts, services, credentials, tokens) and
    a task graph (goal/subgoal status), anchored by shared credential->host edges.
    render() summarizes owned vs locked assets and surfaces a reachable pivot."""

    name = 'graph'

    def __init__(self, goal_host='internal'):
        self.assets = nx.DiGraph()
        self.tasks = nx.DiGraph()
        self.goal_host = goal_host
        self.tasks.add_node('goal', label=f'reach crown jewel on {goal_host}', status='open')

    def _host(self, h):
        if not self.assets.has_node(('host', h)):
            self.assets.add_node(('host', h), kind='host', owned=False)
        return ('host', h)

    def update(self, obs):
        t = obs['type']
        if t == 'endpoint':
            hn = self._host(obs['host'])
            self.assets.add_node(('ep', obs['host'], obs['path']), kind='endpoint', status=obs['status'])
            self.assets.add_edge(hn, ('ep', obs['host'], obs['path']), rel='has')
        elif t == 'token':
            hn = self._host(obs['host'])
            self.assets.nodes[hn]['owned'] = True
            self.assets.add_node(('tok', obs['host']), kind='token', value=obs['token'])
            self.assets.add_edge(hn, ('tok', obs['host']), rel='owns')
        elif t == 'cred':
            cn = ('cred', obs['user'])
            self.assets.add_node(cn, kind='cred', user=obs['user'], password=obs['password'])
            self.assets.add_edge(cn, self._host(obs['for_host']), rel='unlocks')  # ANCHOR
        elif t == 'jewel':
            self._host(obs['host'])
            self.assets.nodes[self._host(obs['host'])]['jewel'] = True
            if obs['host'] == self.goal_host:
                self.tasks.nodes['goal']['status'] = 'done'
        elif t == 'blocked':
            self._host(obs['host'])

    def pivots(self):
        """Credentials that unlock a not-yet-owned host (reachable next steps)."""
        out = []
        for n, d in self.assets.nodes(data=True):
            if d.get('kind') == 'cred':
                for _, hn, ed in self.assets.out_edges(n, data=True):
                    if ed.get('rel') == 'unlocks' and not self.assets.nodes[hn].get('owned'):
                        out.append((hn[1], d['user'], d['password']))
        return out

    def render(self):
        owned = [n[1] for n, d in self.assets.nodes(data=True) if d.get('kind') == 'host' and d.get('owned')]
        locked = [n[1] for n, d in self.assets.nodes(data=True) if d.get('kind') == 'host' and not d.get('owned')]
        lines = ['ASSET GRAPH:']
        lines.append('  owned hosts: ' + (', '.join(owned) or '(none)'))
        lines.append('  other hosts: ' + (', '.join(locked) or '(none)'))
        for host, user, pw in self.pivots():
            lines.append(f"  PIVOT AVAILABLE: credential {user}/{pw} unlocks host '{host}' (not yet owned)")
        goal = self.tasks.nodes['goal']
        lines.append(f"TASK: {goal['label']} [{goal['status']}]")
        return '\n'.join(lines)


def make(name, goal_host='internal'):
    return GraphKnowledge(goal_host) if name == 'graph' else FlatKnowledge()
