// Copyright 2022 Tigris Data, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package middleware

import (
	"context"

	middleware "github.com/grpc-ecosystem/go-grpc-middleware/v2"
	"github.com/tigrisdata/tigris/server/metrics"
	"github.com/tigrisdata/tigris/server/request"
	"github.com/tigrisdata/tigris/util"
	ulog "github.com/tigrisdata/tigris/util/log"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
)

const (
	TigrisStreamSpan string = "rpcstream"
)

type wrappedStream struct {
	*middleware.WrappedServerStream
	spanMeta *metrics.SpanMeta
}

func getNoTracingMethods() []string {
	return []string{
		"/HealthAPI/Health",
	}
}

func traceMethod(fullMethod string) bool {
	for _, method := range getNoTracingMethods() {
		if method == fullMethod {
			return false
		}
	}
	return true
}

func traceUnary() func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		if !traceMethod(info.FullMethod) {
			resp, err := handler(ctx, req)
			return resp, err
		}
		reqMetadata, err := request.GetRequestMetadata(ctx)
		if err != nil {
			ulog.E(err)
		}
		tags := reqMetadata.GetInitialTags()
		spanMeta := metrics.NewSpanMeta(util.Service, info.FullMethod, metrics.GrpcSpanType, tags)
		spanMeta.AddTags(metrics.GetDbCollTagsForReq(req))
		ctx = spanMeta.StartTracing(ctx, false)
		resp, err := handler(ctx, req)
		if err != nil {
			// Request had an error
			spanMeta.CountErrorForScope(metrics.ErrorRequests, spanMeta.GetRequestErrorTags(err))
			_ = spanMeta.FinishWithError(ctx, "request", err)
			spanMeta.RecordDuration(metrics.RequestsRespTime, spanMeta.GetRequestTimerTags())
			ulog.E(err)
			return nil, err
		}
		// Request was ok
		spanMeta.CountOkForScope(metrics.OkRequests, spanMeta.GetRequestOkTags())
		spanMeta.CountReceivedBytes(metrics.BytesReceived, spanMeta.GetNetworkTags(), proto.Size(req.(proto.Message)))
		spanMeta.CountSentBytes(metrics.BytesSent, spanMeta.GetNetworkTags(), proto.Size(resp.(proto.Message)))
		_ = spanMeta.FinishTracing(ctx)
		spanMeta.RecordDuration(metrics.RequestsRespTime, spanMeta.GetRequestTimerTags())
		return resp, err
	}
}

func traceStream() grpc.StreamServerInterceptor {
	return func(srv interface{}, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		wrapped := &wrappedStream{WrappedServerStream: middleware.WrapServerStream(stream)}
		wrapped.WrappedContext = stream.Context()
		if !traceMethod(info.FullMethod) {
			err := handler(srv, wrapped)
			return err
		}
		reqMetadata, err := request.GetRequestMetadata(wrapped.WrappedContext)
		if err != nil {
			ulog.E(err)
		}
		tags := reqMetadata.GetInitialTags()
		spanMeta := metrics.NewSpanMeta(util.Service, info.FullMethod, metrics.GrpcSpanType, tags)
		wrapped.spanMeta = spanMeta
		wrapped.WrappedContext = spanMeta.StartTracing(wrapped.WrappedContext, false)
		err = handler(srv, wrapped)
		if err != nil {
			spanMeta.CountErrorForScope(metrics.ErrorRequests, spanMeta.GetRequestErrorTags(err))
			wrapped.WrappedContext = spanMeta.FinishWithError(wrapped.WrappedContext, "request", err)
			spanMeta.RecordDuration(metrics.RequestsRespTime, spanMeta.GetRequestTimerTags())
			ulog.E(err)
			return err
		}
		spanMeta.CountOkForScope(metrics.OkRequests, spanMeta.GetRequestOkTags())
		wrapped.WrappedContext = spanMeta.FinishTracing(wrapped.WrappedContext)
		spanMeta.RecordDuration(metrics.RequestsRespTime, spanMeta.GetRequestTimerTags())
		return err
	}
}

func (w *wrappedStream) RecvMsg(m interface{}) error {
	parentSpanMeta := w.spanMeta
	if parentSpanMeta == nil {
		err := w.ServerStream.RecvMsg(m)
		return err
	}
	childSpanMeta := metrics.NewSpanMeta(TigrisStreamSpan, "RecvMsg", metrics.GrpcSpanType, parentSpanMeta.GetRequestOkTags())
	w.WrappedContext = childSpanMeta.StartTracing(w.WrappedContext, true)
	err := w.ServerStream.RecvMsg(m)
	parentSpanMeta.AddTags(metrics.GetDbCollTagsForReq(m))
	childSpanMeta.AddTags(metrics.GetDbCollTagsForReq(m))
	parentSpanMeta.CountReceivedBytes(metrics.BytesReceived, parentSpanMeta.GetNetworkTags(), proto.Size(m.(proto.Message)))
	w.WrappedContext = childSpanMeta.FinishTracing(w.WrappedContext)
	return err
}

func (w *wrappedStream) SendMsg(m interface{}) error {
	parentSpanMeta := w.spanMeta
	if parentSpanMeta == nil {
		err := w.ServerStream.SendMsg(m)
		return err
	}
	childSpanMeta := metrics.NewSpanMeta(TigrisStreamSpan, "SendMsg", metrics.GrpcSpanType, parentSpanMeta.GetRequestOkTags())
	w.WrappedContext = childSpanMeta.StartTracing(w.WrappedContext, true)
	err := w.ServerStream.SendMsg(m)
	parentSpanMeta.AddTags(metrics.GetDbCollTagsForReq(m))
	childSpanMeta.AddTags(metrics.GetDbCollTagsForReq(m))
	parentSpanMeta.CountSentBytes(metrics.BytesSent, parentSpanMeta.GetNetworkTags(), proto.Size(m.(proto.Message)))
	w.WrappedContext = childSpanMeta.FinishTracing(w.WrappedContext)
	return err
}
