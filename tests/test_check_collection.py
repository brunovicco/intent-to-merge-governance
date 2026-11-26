"""Check collection regressions exercised through the preflight API boundary."""
import unittest
from urllib.parse import parse_qs, urlsplit

from intent_merge.github import GitHub, GitHubObservationError, policy_from, preflight
from test_integration_v05 import FixtureAPI, HEAD, BASE, ROOT


def envelope(rows, count=None):
    return {'total_count': len(rows) if count is None else count, 'check_runs': rows}


class CheckCollectionTests(unittest.TestCase):
    def setUp(self):
        self.fixture = FixtureAPI()
        self.policy = policy_from(ROOT / 'examples/github-policy.toml')
        self.check = {**self.fixture.checks[0], 'external_id': None}

    def observe(self, responses, *, suites=None, publish=False):
        self.queries = []
        fixture = self.fixture
        if suites is None:
            suites = {'total_count': 1, 'check_suites': [{'id': 1}]}

        class Client(GitHub):
            def request(client, path, payload=None, **kwargs):
                kind = urlsplit(path).path.rsplit('/', 1)[-1]
                query = parse_qs(urlsplit(path).query)
                if payload is not None:
                    return fixture.request(path, payload)
                if kind == 'check-suites':
                    return suites
                if kind == 'check-runs':
                    self.queries.append(query)
                    item = responses[int(query['page'][0]) - 1]
                    if isinstance(item, Exception):
                        raise item
                    return item
                if kind in ('files', 'reviews'):
                    return getattr(fixture, kind)
                return fixture.request(path)

        return preflight(Client('fixture', installation_app_id=789), 'OWNER/REPO', 1,
                         self.policy, publish=publish)

    def test_advertised_two_with_older_success_cannot_pass(self):
        try:
            report = self.observe([envelope([self.check], 2)], publish=True)
        except GitHubObservationError:
            pass
        else:
            self.fail(f'incomplete collection produced {report["decision"]}')
        self.assertFalse(self.fixture.posts)

    def test_same_id_conflict_hidden_by_app_filter_cannot_pass(self):
        other = {**self.check, 'app': {'id': 12346}, 'conclusion': 'failure'}
        try:
            report = self.observe([envelope([self.check, other])], publish=True)
        except GitHubObservationError:
            pass
        else:
            self.fail(f'contradictory collection produced {report["decision"]}')
        self.assertFalse(self.fixture.posts)

    def test_preserves_highest_id_selection_with_all_runs(self):
        newer = {**self.check, 'id': 7, 'conclusion': 'failure',
                 'completed_at': '2025-01-01T00:00:00Z'}
        older = {**self.check, 'completed_at': '2026-01-01T00:00:00Z'}
        for rows in ([older, newer], [newer, older]):
            with self.subTest(first=rows[0]['id']):
                self.assertEqual(self.observe([envelope(rows)])['decision'], 'BLOCK')
                self.assertEqual(self.queries, [{'filter': ['all'], 'per_page': ['100'], 'page': ['1']}])

    def rows(self, size):
        return [{**self.check, 'id': i} for i in range(1, size + 1)]

    def test_valid_page_boundaries(self):
        for total in (0, 99, 100, 101, 200, 3000):
            with self.subTest(total=total):
                rows = self.rows(total)
                pages = [envelope(rows[i:i+100], total) for i in range(0, total, 100)]
                self.assertEqual(self.observe(pages or [envelope([])])['decision'], 'PASS' if total else 'BLOCK')
                self.assertEqual(len(self.queries), max(1, (total + 99) // 100))
                self.assertTrue(all(q['per_page'] == ['100'] for q in self.queries))

    def test_count_and_container_matrix(self):
        full = self.rows(100)
        tail = {**self.check, 'id': 101}
        cases = {
            'missing': [{'check_runs': [self.check]}],
            'bad container': [None],
            'bad array': [{'total_count': 1, 'check_runs': {}}],
            'zero with record': [envelope([self.check], 0)],
            'early empty': [envelope(full, 101), envelope([], 101)],
            'early short': [envelope(full[:-1], 101)],
            'excess on first page': [envelope(full + [tail], 101)],
            'excess on last page': [envelope(full, 101), envelope([tail, self.check], 101)],
            'count increased': [envelope(full, 101), envelope([tail], 102)],
            'count decreased': [envelope(full, 102), envelope([tail], 101)],
            'parse failure after full page': [envelope(full, 101), GitHubObservationError('invalid GitHub response JSON')],
            'repeated page': [envelope(full, 200), envelope(full, 200)],
            'over local page limit': [envelope(full, 3001)],
            'transport failure after full page': [envelope(full, 101), GitHubObservationError('GitHub transport failure')],
        }
        for count in (None, -1, True, False, 1.0, '1'):
            cases[repr(count)] = [{'total_count': count, 'check_runs': [self.check]}]
        for label, pages in cases.items():
            with self.subTest(case=label), self.assertRaises(GitHubObservationError):
                self.observe(pages, publish=True)
        self.assertFalse(self.fixture.posts)

    def test_identity_faults_within_and_across_pages(self):
        for change in ({}, {'app': {'id': 12346}}, {'name': 'another check'},
                       {'head_sha': BASE}, {'conclusion': 'failure'},
                       {'status': 'queued', 'conclusion': None}, {'external_id': 'another-id'}):
            other = {**self.check, **change}
            for across in (False, True):
                first_page = [self.check, *[{**self.check, 'id': i} for i in range(10, 109)]]
                pages = ([envelope(first_page, 101), envelope([other], 101)]
                         if across else [envelope([self.check, other])])
                with self.subTest(change=change, across=across), self.assertRaises(GitHubObservationError):
                    self.observe(pages)

    def test_unrelated_records_are_validated_and_nullable_fields_are_allowed(self):
        other = {**self.check, 'id': 9, 'name': 'unrelated', 'app': None,
                 'status': 'in_progress', 'conclusion': None, 'started_at': None, 'check_suite': None}
        self.assertEqual(self.observe([envelope([self.check, other])])['decision'], 'PASS')
        self.assertEqual(self.observe([envelope([{**other, 'name': self.check['name'], 'external_id': None}])])['decision'],
                         'BLOCK')
        for field in ('id', 'app', 'external_id', 'conclusion'):
            with self.subTest(missing=field), self.assertRaises(GitHubObservationError):
                self.observe([envelope([self.check, {k: v for k, v in other.items() if k != field}])])
        for change in ({'id': False}, {'id': 9.0}, {'id': '9'}, {'id': -9}, {'id': 0}, {'id': None},
                       {'app': {'id': True}}, {'app': 'wrong'}, {'external_id': []}, {'head_sha': 'bad'},
                       {'name': None}, {'status': {}}, {'conclusion': 'success'}):
            with self.subTest(change=change), self.assertRaises(GitHubObservationError):
                self.observe([envelope([self.check, {**other, **change}])])

    def test_suite_cap_stops_before_listing_runs(self):
        for total in (1000, 1001):
            with self.subTest(total=total), self.assertRaises(GitHubObservationError):
                self.observe([], suites={'total_count': total, 'check_suites': [{'id': 1}]})
            self.assertEqual(self.queries, [])

    def test_suite_probe_requires_a_valid_count_and_first_page(self):
        for suites in ({'check_suites': []}, {'total_count': True, 'check_suites': [{'id': 1}]},
                       {'total_count': 0, 'check_suites': [{'id': 1}]},
                       {'total_count': 1, 'check_suites': []}, {'total_count': 1, 'check_suites': [{'id': True}]}):
            with self.subTest(suites=suites), self.assertRaises(GitHubObservationError):
                self.observe([], suites=suites)
            self.assertEqual(self.queries, [])
        self.assertEqual(self.observe([envelope([self.check])],
                                     suites={'total_count': 999, 'check_suites': [{'id': 1}]})['decision'], 'PASS')
        self.assertEqual(self.observe([envelope([])],
                                     suites={'total_count': 0, 'check_suites': []})['decision'], 'BLOCK')
