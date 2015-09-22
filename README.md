# splunk-notes
Splunk notes.

## Parse access logs

```
{{{"some search" sourcetype="LogFiles.access_combined_wcookie" | rex field=_raw "] \"(?<httpMethod>[^\s]+) (?<urlPath>[^\s]+) (?<httpVersion>[^\s]+)\" (?<httpStatus>[^\s]+) (?<respBytes>[^\s]*) (?<respTimeMillis>[^\s]*) \"(?<userAgent>.*)\" \"(?<referrerUrl>.*)\""}}}
```

## Filters

Regex:

```
{{{ "some search" | regex someFieldName = ".*SOME.*REGEX.*"}}}
```

Negative regex:

```
{{{ "some search" | regex someFieldName != ".*SOME.*REGEX.*"}}}
```

Where:

```
{{{ "some search" | where someFieldName = "someValue"}}}
```

Negative where:

```
{{{ "some search" | where someFieldName != "someValue"}}}
```

## Find User Agents by Referrer & URL without query

```
{{{"some search" sourcetype="LogFiles.access_combined_wcookie" | rex field=_raw "] \"(?<httpMethod>[^\s]+) (?<urlPath>[^\s]+) (?<httpVersion>[^\s]+)\" (?<httpStatus>[^\s]+) (?<respBytes>[^\s]*) (?<respTimeMillis>[^\s]*) \"(?<userAgent>.*)\" \"(?<referrerUrl>.*)\"" | rex field=urlPath "(?<nonQuery>[^\?]*).*" | eval urls=referrerUrl + " -> " + nonQuery | chart count by userAgent, urls}}}
```

## Multi-line queries ("transactions")

```
{{{ "" | transaction startswith="Request:" endswith=("Unable to add to cart") maxevents=4}}}
```
