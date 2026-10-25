import {test, expect} from '@playwright/test';
import {routeLatency} from '../src/route-latency';

test('latency follows active exits and excludes unused or failed samples', () => {
  const status = {up: true, routes: [{provider: 'proton'}], providers: {
    proton: {active: 'current', egress: {current: {ok: true, latency_ms: 123.4, checked_at: 100}, old: {ok: true, latency_ms: 1, checked_at: 200}}},
    unused: {active: 'other', egress: {other: {ok: true, latency_ms: 2, checked_at: 300}}},
  }};
  expect(routeLatency(status)).toEqual({ms: 123, checkedAt: 100, provider: 'proton'});
  expect(routeLatency({...status, up: false})).toBeNull();
  status.providers.proton.egress.current.ok = false;
  expect(routeLatency(status)).toBeNull();
});

test('fallback and invalid timings cannot claim latency for the selected exit', () => {
  const status = {up: true, routes: [{provider: 'warp'}], providers: {warp: {active: 'socks', fallback: {active: true}, egress: {socks: {ok: true, latency_ms: 99, checked_at: 100}}}}};
  expect(routeLatency(status)).toBeNull();
  status.providers.warp.fallback.active = false;
  status.providers.warp.egress.socks.latency_ms = NaN;
  expect(routeLatency(status)).toBeNull();
  expect(routeLatency(null)).toBeNull();
});
