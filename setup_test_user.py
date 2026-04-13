#!/usr/bin/env python3
"""
Setup script to create test user for the AI De-identification System
Creates the demo user: E-Hari with password: Muxbx@hari1
"""

import sys
import os
from pathlib import Path
import logging

# Add the current directory to Python path
sys.path.insert(0, str(Path(__file__).parent))

from simple_database import create_database, User, hash_password

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def setup_test_user():
    """Create the test user if it doesn't exist"""
    try:
        # Initialize database
        logger.info("Initializing database...")
        engine, SessionLocal = create_database()

        # Create session
        db = SessionLocal()

        # Check if test user already exists
        existing_user = db.query(User).filter(User.username == "E-Hari").first()

        if existing_user:
            logger.info("Test user 'E-Hari' already exists")
            # Update password just in case
            existing_user.hashed_password = hash_password("Muxbx@hari1")
            db.commit()
            logger.info("Updated test user password")
        else:
            # Create test user
            logger.info("Creating test user 'E-Hari'...")

            test_user = User(
                username="E-Hari",
                email="ehari@example.com",
                full_name="E-Hari Demo User",
                hashed_password=hash_password("Muxbx@hari1"),
                role="admin",  # Give admin role for testing
                is_active=True
            )

            db.add(test_user)
            db.commit()
            db.refresh(test_user)

            logger.info(f"Test user created successfully with ID: {test_user.id}")

        # Create additional test user for variety
        test_user2 = db.query(User).filter(User.username == "testuser").first()
        if not test_user2:
            test_user2 = User(
                username="testuser",
                email="testuser@example.com",
                full_name="Test User",
                hashed_password=hash_password("password123"),
                role="user",
                is_active=True
            )
            db.add(test_user2)
            db.commit()
            logger.info("Additional test user 'testuser' created")

        # Verify users exist
        all_users = db.query(User).all()
        logger.info(f"Total users in database: {len(all_users)}")
        for user in all_users:
            logger.info(f"  - {user.username} ({user.email}) - Role: {user.role}")

        db.close()
        logger.info("Database setup completed successfully!")

        return True

    except Exception as e:
        logger.error(f"Failed to setup test user: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    print("=== AI De-identification System - Test User Setup ===")
    print("Setting up demo user: E-Hari / Muxbx@hari1")
    print()

    success = setup_test_user()

    if success:
        print("\n✅ Test user setup completed successfully!")
        print("You can now login with:")
        print("  Username: E-Hari")
        print("  Password: Muxbx@hari1")
    else:
        print("\n❌ Test user setup failed. Check the logs above.")
        sys.exit(1)