#!/usr/bin/env python3
"""
ARACHNE - Temporal Analyzer
Detects time-based vulnerabilities (Blind SQLi, SSRF, etc.) by analyzing response delays.
Uses statistical baselining to filter out network noise.
"""
import asyncio
import time
import statistics
from dataclasses import dataclass
from typing import Dict, List, Tuple, Optional, Callable, Any
import numpy as np
from scipy import stats  # Optional, for advanced statistical tests

@dataclass
class TemporalSignature:
    """Represents the time characteristics of a request/response pair."""
    url: str
    payload: str
    response_time: float  # in seconds
    status_code: int
    response_size: int
    timestamp: float

class TemporalAnalyzer:
    """
    Measures the heartbeat of an application. Sometimes, the silence screams.
    """

    def __init__(self, baseline_samples: int = 10, delay_threshold_stddev: float = 3.0):
        """
        Args:
            baseline_samples: Number of normal requests to establish baseline timing.
            delay_threshold_stddev: Number of standard deviations above mean to flag as delayed.
        """
        self.baseline_samples = baseline_samples
        self.delay_threshold_stddev = delay_threshold_stddev
        self.baseline_times: List[float] = []
        self.baseline_mean: float = 0.0
        self.baseline_std: float = 0.0
        self.baseline_established: bool = False

    async def establish_baseline(self, request_func: Callable[[], Any]) -> bool:
        """
        Establish a baseline of normal response times.
        request_func: An async function that makes a benign request and returns (response_time, status_code, size).
        """
        self.baseline_times.clear()
        print(f"[*] Establishing temporal baseline with {self.baseline_samples} samples...")
        for i in range(self.baseline_samples):
            try:
                resp_time, status, size = await request_func()
                if 200 <= status < 500:  # Consider only somewhat valid responses
                    self.baseline_times.append(resp_time)
                await asyncio.sleep(0.5)  # Be polite
            except Exception as e:
                print(f"[-] Baseline sample {i} failed: {e}")
                continue

        if len(self.baseline_times) >= 5:  # Need a minimum to be meaningful
            self.baseline_mean = statistics.mean(self.baseline_times)
            self.baseline_std = statistics.stdev(self.baseline_times) if len(self.baseline_times) > 1 else 0.1
            self.baseline_established = True
            print(f"[+] Baseline established: mean={self.baseline_mean:.3f}s, std={self.baseline_std:.3f}s")
            return True
        else:
            print("[-] Could not establish a reliable baseline.")
            return False

    def is_delayed(self, response_time: float) -> Tuple[bool, float]:
        """
        Determine if a response time is statistically anomalous (delayed).
        Returns: (is_delayed, z_score)
        """
        if not self.baseline_established or self.baseline_std == 0:
            # If no baseline, use a simple heuristic threshold (2 seconds)
            return (response_time > 2.0, response_time)

        z_score = (response_time - self.baseline_mean) / self.baseline_std
        return (z_score > self.delay_threshold_stddev, z_score)

    async def test_time_based_payload(self,
                                      payload: str,
                                      request_func: Callable[[str], Any],
                                      control_payload: Optional[str] = None) -> Dict[str, Any]:
        """
        Test a single payload for time-based delays.
        request_func: An async function that takes a payload string and returns (response_time, status_code, size).
        control_payload: A payload that should NOT cause a delay (for comparison).
        """
        if not self.baseline_established:
            # Run a quick baseline with the control payload if provided
            if control_payload:
                control_times = []
                for _ in range(3):
                    rt, status, _ = await request_func(control_payload)
                    control_times.append(rt)
                    await asyncio.sleep(0.3)
                temp_mean = statistics.mean(control_times)
                temp_std = statistics.stdev(control_times) if len(control_times) > 1 else 0.1
                self.baseline_mean, self.baseline_std = temp_mean, temp_std
                self.baseline_established = True
            else:
                # No baseline, will use absolute threshold
                pass

        # Test the payload multiple times to be sure
        test_results = []
        for i in range(3):  # Triple-tap for confidence
            start = time.perf_counter()
            resp_time, status_code, size = await request_func(payload)
            test_results.append(resp_time)
            if i < 2:
                await asyncio.sleep(1)  # Space out the requests

        median_time = statistics.median(test_results)
        is_delayed, z_score = self.is_delayed(median_time)

        result = {
            'payload': payload,
            'response_times': test_results,
            'median_time': median_time,
            'is_delayed': is_delayed,
            'z_score': z_score,
            'baseline_mean': self.baseline_mean,
            'baseline_std': self.baseline_std,
            'status_code': status_code,
            'response_size': size
        }

        # Heuristic: If all three requests are delayed consistently, confidence is high
        if is_delayed and all(t > (self.baseline_mean + self.baseline_std) for t in test_results):
            result['confidence'] = 'high'
        elif is_delayed:
            result['confidence'] = 'medium'
        else:
            result['confidence'] = 'low'

        return result

    async def differential_timing_attack(self,
                                         payload_true: str,
                                         payload_false: str,
                                         request_func: Callable[[str], Any],
                                         samples: int = 7) -> Dict[str, Any]:
        """
        Perform a differential timing attack (e.g., for blind SQLi boolean extraction).
        Measures if there's a statistically significant difference between response times
        for a 'true' condition payload and a 'false' condition payload.
        """
        print(f"[*] Conducting differential timing attack ({samples} samples per condition)...")

        times_true = []
        times_false = []

        for i in range(samples):
            # Interleave requests to account for network variability
            rt_t, status_t, _ = await request_func(payload_true)
            times_true.append(rt_t)
            await asyncio.sleep(0.3)

            rt_f, status_f, _ = await request_func(payload_false)
            times_false.append(rt_f)
            if i < samples - 1:
                await asyncio.sleep(0.5)

        # Basic statistical test: Mann-Whitney U (non-parametric, doesn't assume normal distribution)
        try:
            u_stat, p_value = stats.mannwhitneyu(times_true, times_false, alternative='two-sided')
        except ImportError:
            # Fallback if scipy not available: simple mean comparison
            p_value = 0.05
            u_stat = 0
            mean_true = statistics.mean(times_true)
            mean_false = statistics.mean(times_false)
            # Very crude p-value simulation
            if abs(mean_true - mean_false) > (statistics.stdev(times_true + times_false) * 1.5):
                p_value = 0.01

        mean_true = statistics.mean(times_true)
        mean_false = statistics.mean(times_false)
        std_true = statistics.stdev(times_true) if len(times_true) > 1 else 0
        std_false = statistics.stdev(times_false) if len(times_false) > 1 else 0

        # Result interpretation
        significant = p_value < 0.05  # 95% confidence
        true_slower = mean_true > mean_false

        return {
            'significant_difference': significant,
            'p_value': p_value,
            'u_statistic': u_stat,
            'mean_true': mean_true,
            'mean_false': mean_false,
            'std_true': std_true,
            'std_false': std_false,
            'times_true': times_true,
            'times_false': times_false,
            'interpretation': f"Condition 'true' is {'slower' if true_slower else 'faster'} than 'false' with {100*(1-p_value):.1f}% confidence."
        }


# Example async request function signature:
# async def example_request(payload: str) -> Tuple[float, int, int]:
#     start = time.perf_counter()
#     async with aiohttp.ClientSession() as session:
#         async with session.get(f"http://target.com/?id={payload}") as resp:
#             resp_time = time.perf_counter() - start
#             return resp_time, resp.status, len(await resp.text())

if __name__ == "__main__":
    print("[*] Temporal Analyzer module loaded.")
    print("[*] This module must be integrated with an async HTTP client to be functional.")
    print("[*] Run from within ARACHNE core or with a provided request function.")