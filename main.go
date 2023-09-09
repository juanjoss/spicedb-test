package main

import (
	"context"
	"log"

	pb "github.com/authzed/authzed-go/proto/authzed/api/v1"
	"github.com/authzed/authzed-go/v1"
	"github.com/authzed/grpcutil"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const (
	schema = `
		definition namespace/user {}

		definition namespace/payment {
			relation payer: namespace/user
			relation collector: namespace/user
			relation marketplace_owner: namespace/user
		
			permission view = payer + collector + marketplace_owner
			permission some_restricted_permission = marketplace_owner
		}
	`

	host = "localhost:50051"
	key  = "somekey"
)

func main() {
	ctx := context.Background()

	client, err := authzed.NewClient(
		host,
		grpcutil.WithInsecureBearerToken(key),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		log.Fatalf("unable to initialize client: %s", err)
	}

	if err := writeSchema(ctx, client, schema); err != nil {
		log.Fatalf("unable to write schema: %s", err)
	}

	if err := writeRelationships(ctx, client); err != nil {
		log.Fatalf("unable to write relations: %s", err)
	}

	evaluatePermissions(ctx, client)
}

func writeSchema(ctx context.Context, client *authzed.Client, schema string) error {
	request := &pb.WriteSchemaRequest{
		Schema: schema,
	}

	res, err := client.WriteSchema(ctx, request)
	if err != nil {
		return err
	}

	log.Println("write schema response:", res)

	return nil
}

func writeRelationships(ctx context.Context, client *authzed.Client) error {
	request := &pb.WriteRelationshipsRequest{
		Updates: []*pb.RelationshipUpdate{
			{
				Operation: pb.RelationshipUpdate_OPERATION_TOUCH,
				Relationship: &pb.Relationship{
					Resource: &pb.ObjectReference{
						ObjectType: "namespace/payment",
						ObjectId:   "payment_1",
					},
					Relation: "payer",
					Subject: &pb.SubjectReference{
						Object: &pb.ObjectReference{
							ObjectType: "namespace/user",
							ObjectId:   "bob",
						},
					},
				},
			},
			{
				Operation: pb.RelationshipUpdate_OPERATION_TOUCH,
				Relationship: &pb.Relationship{
					Resource: &pb.ObjectReference{
						ObjectType: "namespace/payment",
						ObjectId:   "payment_1",
					},
					Relation: "collector",
					Subject: &pb.SubjectReference{
						Object: &pb.ObjectReference{
							ObjectType: "namespace/user",
							ObjectId:   "alice",
						},
					},
				},
			},
			{
				Operation: pb.RelationshipUpdate_OPERATION_TOUCH,
				Relationship: &pb.Relationship{
					Resource: &pb.ObjectReference{
						ObjectType: "namespace/payment",
						ObjectId:   "payment_2",
					},
					Relation: "collector",
					Subject: &pb.SubjectReference{
						Object: &pb.ObjectReference{
							ObjectType: "namespace/user",
							ObjectId:   "john",
						},
					},
				},
			},
			{
				Operation: pb.RelationshipUpdate_OPERATION_TOUCH,
				Relationship: &pb.Relationship{
					Resource: &pb.ObjectReference{
						ObjectType: "namespace/payment",
						ObjectId:   "payment_2",
					},
					Relation: "marketplace_owner",
					Subject: &pb.SubjectReference{
						Object: &pb.ObjectReference{
							ObjectType: "namespace/user",
							ObjectId:   "doe",
						},
					},
				},
			},
		},
	}

	resp, err := client.WriteRelationships(context.Background(), request)
	if err != nil {
		return err
	}

	log.Println("write relationships response:", resp)

	return nil
}

func evaluatePermissions(ctx context.Context, client *authzed.Client) {
	// define principals
	bob := &pb.SubjectReference{
		Object: &pb.ObjectReference{
			ObjectType: "namespace/user",
			ObjectId:   "bob",
		},
	}

	alice := &pb.SubjectReference{
		Object: &pb.ObjectReference{
			ObjectType: "namespace/user",
			ObjectId:   "alice",
		},
	}

	john := &pb.SubjectReference{
		Object: &pb.ObjectReference{
			ObjectType: "namespace/user",
			ObjectId:   "john",
		},
	}

	doe := &pb.SubjectReference{
		Object: &pb.ObjectReference{
			ObjectType: "namespace/user",
			ObjectId:   "doe",
		},
	}

	// define resources
	payment1 := &pb.ObjectReference{
		ObjectType: "namespace/payment",
		ObjectId:   "payment_1",
	}

	payment2 := &pb.ObjectReference{
		ObjectType: "namespace/payment",
		ObjectId:   "payment_2",
	}

	// who can view payment_1?

	if err := checkPermissions(ctx, client, bob, "view", payment1); err != nil {
		log.Fatalf("failed to check permission: %s", err)
	}

	if err := checkPermissions(ctx, client, alice, "view", payment1); err != nil {
		log.Fatalf("failed to check permission: %s", err)
	}

	if err := checkPermissions(ctx, client, john, "view", payment1); err != nil {
		log.Fatalf("failed to check permission: %s", err)
	}

	if err := checkPermissions(ctx, client, doe, "view", payment1); err != nil {
		log.Fatalf("failed to check permission: %s", err)
	}

	// who can view payment_2?

	if err := checkPermissions(ctx, client, bob, "view", payment2); err != nil {
		log.Fatalf("failed to check permission: %s", err)
	}

	if err := checkPermissions(ctx, client, alice, "view", payment2); err != nil {
		log.Fatalf("failed to check permission: %s", err)
	}

	if err := checkPermissions(ctx, client, john, "view", payment2); err != nil {
		log.Fatalf("failed to check permission: %s", err)
	}

	if err := checkPermissions(ctx, client, doe, "view", payment2); err != nil {
		log.Fatalf("failed to check permission: %s", err)
	}

	// who has some_restricted_permission?

	if err := checkPermissions(ctx, client, bob, "some_restricted_permission", payment2); err != nil {
		log.Fatalf("failed to check permission: %s", err)
	}

	if err := checkPermissions(ctx, client, alice, "some_restricted_permission", payment2); err != nil {
		log.Fatalf("failed to check permission: %s", err)
	}

	if err := checkPermissions(ctx, client, john, "some_restricted_permission", payment2); err != nil {
		log.Fatalf("failed to check permission: %s", err)
	}

	if err := checkPermissions(ctx, client, doe, "some_restricted_permission", payment2); err != nil {
		log.Fatalf("failed to check permission: %s", err)
	}
}

func checkPermissions(ctx context.Context, client *authzed.Client, subject *pb.SubjectReference, action string, resource *pb.ObjectReference) error {
	res, err := client.CheckPermission(ctx, &pb.CheckPermissionRequest{
		Resource:   resource,
		Permission: action,
		Subject:    subject,
	})
	if err != nil {
		return err
	}

	log.Printf("can %s %s %s? %s\n", subject.Object.ObjectId, action, resource.ObjectId, res.Permissionship)

	return nil
}
