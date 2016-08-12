import operator
import gevent
from oslo_utils.timeutils import StopWatch
from collections import defaultdict
from collections import deque
from six import wraps


def construct_stats_collector(stats_enabled=False):
    if stats_enabled:
        return StatsCollector()
    else:
        return NoOpStatsCollector()


class StatsCollector(object):
    """
    Simple stats collector for api server, collecting stats on events that could be function calls or sections
    within functions

    """

    def __init__(self, enabled=False):
        self.events = defaultdict(deque)
        self.order = []

    def start(self, event_id):
        """
        Start event for id
        Args:
            event_id:

        Returns:

        """
        if event_id not in self.events:
            self.order.append(event_id)
        watches = self.events[event_id]
        watch = StopWatch()
        watches.append(watch)
        watch.start()

    def end(self, event_id):
        """
        end event for id
        Args:
            event_id:

        Returns:

        """
        self.events[event_id][-1].stop()

    def elapsed(self, event_id):
        """
        time elapsed for an event, returns a list of total time for an event and list of elasped times if the
        event occured multiple times
        Args:
            event_id:

        Returns: (total, List[elapsed times])

        """
        watches = self.events.get(event_id)
        elapsed = [watches.popleft().elapsed() for _ in range(len(watches))]
        return elapsed, reduce(operator.add, elapsed, 0)

    def print_stats(self):
        print "%30s Event Stats %30s" % ("=" * 30, "=" * 30)
        print ([(event, self.elapsed(event)) for event in self.order])
        print "%60s" % ("=" * 60)

    @staticmethod
    def get_local_stats_obj():
        """
        get stats object
        Returns:

        """
        return gevent.getcurrent().stats


def collect_stats(func):
    """
    Method decorator for collecting stats on a function
    Args:
        func:

    Returns:

    """

    @wraps(func)
    def _collect(*args, **kwargs):
        stats = gevent.getcurrent().stats
        stats.start(func.__name__)
        try:
            return func(*args, **kwargs)
        finally:
            stats.end(func.__name__)

    return _collect


class NoOpStatsCollector(object):

    def _noop(self, *args, **kwargs):
        pass

    def __getattr__(self, item):
        return self._noop