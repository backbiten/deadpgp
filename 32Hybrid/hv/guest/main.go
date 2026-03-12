package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"

	pb "github.com/backbiten/32Hybrid/hv/api/hybridhv/v1"
	"google.golang.org/grpc"
)

type server struct {
	pb.UnimplementedHealthServiceServer
	pb.UnimplementedRunnerServiceServer
}

func (s *server) HealthCheck(ctx context.Context, req *pb.HealthCheckRequest) (*pb.HealthCheckResponse, error) {
	return &pb.HealthCheckResponse{
		Status:      "ok",
		WineVersion: "wine-9.0", // Placeholder
	}, nil
}

func (s *server) RunExe(ctx context.Context, req *pb.RunExeRequest) (*pb.RunExeResponse, error) {
	log.Printf("Executing Win32 Binary: %s", req.ExePath)
	
	cmd := exec.Command("wine", req.ExePath)
	cmd.Args = append(cmd.Args, req.Args...)
	
	// Inject 2038-safe environment
	cmd.Env = append(os.Environ(), req.Env...)
	cmd.Env = append(cmd.Env, "LD_PRELOAD=/usr/lib/32hybrid/shim.so")
	cmd.Env = append(cmd.Env, fmt.Sprintf("WINEPREFIX=%%s", req.WinePrefixId))
	
	// Start the process (non-blocking for this skeleton)
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start wine: %%v", err)
	}

	return &pb.RunExeResponse{
		RunId: "run-12345", // Placeholder
	}, nil
}

func main() {
	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalf("failed to listen: %%v", err)
	}
	s := grpc.NewServer()
	srv := &server{}
	pb.RegisterHealthServiceServer(s, srv)
	pb.RegisterRunnerServiceServer(s, srv)
	
	log.Printf("32HybridHV Guest Agent listening at %%v", lis.Addr())
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %%v", err)
	}
}