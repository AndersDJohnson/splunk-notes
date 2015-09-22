# splunk-notes
Splunk notes.

## Parse Tomcat Access Logs

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

## Correlation search (different event occurrences compared on graph)

```
{{{
host=owbsw2kpwrd0* sourcetype="LogFiles.tomcat-wrapper" "Launching a JVM" | eval event="jvm" | stats count by event, _time | eval occurred=if (count > 0, 1, 0) | append [search host=owbsw2kpwrd0* sourcetype="LogFiles.tomcat-wrapper" "permgen" | eval event="permgen" | stats  count by event, _time  | eval occurred=if (count > 0, 1, 0) ] | search event="jvm"
}}}
```

## Errors by message and host

```
{{{
host=owbswcpcs* sourcetype="LogFiles.tomcat-wrapper" | rex field=_raw "\s*(?<level>[^\s]+).*?\|.*?\|.*?\|(?<msg>.{0,80})" | regex msg!="\s+at" | regex msg!=".*\d+ more" | eval hostMsg=host+msg | chart count by hostMsg | sort by count desc
}}}
```

## Filtering out timestamps and low-level JVM (GC, classloader) from messages

```
{{{
host=owbswjpes* source="E:\\LogFiles\\user-services\\tomcat-wrapper.log" | rex field=_raw "\s*(?<level>[^\s]+).*?\|.*?\|.*?\|(\s*.*?\s\d+.*?(AM|PM))?(?<msg>.{0,80})" | regex msg!="(\[GC)|(Full GC\[)|(PSYoungGen)|(Unloading class)" | timechart limit=0 count by msg span=30min | sort by count desc
}}}
```

## Response times for URLS

```
{{{
"/services/user/V2.0/service/GetUser* " host="owbswjpes0*" sourcetype="LogFiles.access_combined_wcookie" | rex field=_raw "\" [^\s]+ (?<respBytes_>[^\s]+) (?<respTimeMillis_>[^\s]+) " | timechart eval(avg(respTimeMillis_) + stdevp(respTimeMillis_)) AS AvgPlusSDRespTime by host
}}}
```
