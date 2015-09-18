/*
 * Copyright (c) 2013 Juniper Networks, Inc. All rights reserved.
 */

#ifndef SRC_BGP_ROUTING_INSTANCE_ISTATIC_ROUTE_MGR_H_
#define SRC_BGP_ROUTING_INSTANCE_ISTATIC_ROUTE_MGR_H_

#include <stdint.h>

class IStaticRouteMgr {
public:
    virtual ~IStaticRouteMgr() { }

    virtual void ProcessStaticRouteConfig() = 0;
    virtual void UpdateStaticRouteConfig() = 0;
    virtual void FlushStaticRouteConfig() = 0;
    virtual void NotifyAllRoutes() = 0;
    virtual uint32_t GetRouteCount() const = 0;
    virtual uint32_t GetDownRouteCount() const = 0;

private:
    friend class StaticRouteTest;

    virtual void DisableQueue() = 0;
    virtual void EnableQueue() = 0;
    virtual bool IsQueueEmpty() = 0;
};

#endif  // SRC_BGP_ROUTING_INSTANCE_ISTATIC_ROUTE_MGR_H_
